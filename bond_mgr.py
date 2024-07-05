import logging
import re
import os
import traceback
import logging
import re
import os
import traceback
import psutil
import shutil
import datetime as dt
import configparser
from web_manage.cluster.models import ClusterNode
from web_manage.common.utils import FileOp, find_interface_for_ip
from web_manage.common import constants, cmdutils
from web_manage.common.errcode import get_error_result
from web_manage.common.constants import BOND_INFO_DIR



logger = logging.getLogger(__name__)


class BondManager(object):

    def __init__(self):
        self.base_dir = "/proc/net/bonding/"
        self.file_path = "/proc/net/bonding/%s"
        self.bond_path = "/etc/NetworkManager/system-connections/"
        self.common_content = [
            "TYPE=Ethernet",
            "ONBOOT=yes",
            "NM_CONTROLLED=no"
        ]
        self.unbond_common_content = [
            "TYPE=Ethernet",
            "ONBOOT=yes",
        ]
        # self.backup_dir = os.path.join(self.base_dir, 'bond_backup')
        # if not os.path.exists(self.backup_dir):
        #     os.mkdir(self.backup_dir)
        self.mac_regex = r'[A-F0-9]{2}[-:]?[A-F0-9]{2}[-:.]?[A-F0-9]{2}[-:]?[A-F0-9]{2}[-:.]?[A-F0-9]{2}[-:]?[A-F0-9]{2}'
        self.ip_regex = r'((([1-9]?|1\d)\d|2([0-4]\d|5[0-5]))\.){3}(([1-9]?|1\d)\d|2([0-4]\d|5[0-5]))'

    def list_files(self, dir_path):
        file_list = list()
        for file_name in os.listdir(dir_path):
            file_path = os.path.join(dir_path, file_name)
            if os.path.isfile(file_path):
                file_list.append(file_path)
        return file_list

    def update_conf(self, conf, conf_list):
        with open(conf, 'w') as fd:
            fd.write('\n'.join(conf_list))
            fd.write('\n')
            fd.flush()
            os.fsync(fd.fileno())
            fd.close()

        logger.info("file:%s, content:%s" % (conf, conf_list))

    def parse_network_config(self, interface_name):
        config_file = self.bond_path + interface_name + ".nmconnection"

        
        if not os.path.exists(config_file):
            return {}
        
        config = configparser.ConfigParser(allow_no_value=True)  
        config.read(config_file)  

        network_config = {
            'ip': '',
            'netmask': '',
            'gateway': '',
            'dns1': '',
            'dns2': ''
        }

        ipv4_section = config['ipv4']
        if 'address1' in ipv4_section:
            ip_infp = ipv4_section['address1'].split(',')
            if len(ip_infp) > 1:
                network_config['ip'] = ip_infp[0].split('/')[0]
                network_config['netmask'] = self.cidr_to_mask(int(ip_infp[0].split('/')[1]))
                network_config['gateway'] = ip_infp[1]
            else:
                network_config['ip'] = ip_infp[0].split('/')[0]
                
        if 'dns' in ipv4_section:
            dns = ipv4_section['dns'].strip().split(';')
            if len(dns) >1:
                network_config['dns1'] = dns[0].strip()
            if len(dns) > 2:
                network_config['dns1'] = dns[0].strip()
                network_config['dns2'] = dns[1].strip()
            


        return network_config
    
    def parse_bonding_info(self, filename):
        with open(filename, 'r') as file:
            content = file.read()                                              
        mode = re.search(r'Bonding Mode: (.*)', content).group(1)
        if 'round-robin' in mode:
            mode = 0
        elif 'active-backup' in mode:
            mode = 1
        elif 'adaptive load' in mode:
            mode = 6
        # 使用正则表达式提取所需信息
        bond_info = {
            'name': os.path.basename(filename),
            'mode': mode,
            'status': re.search(r'MII Status: (up|down)', content).group(1),
            'slaves': []
        }
    
        for line in content.split('\n'):
            if line.startswith('Slave Interface:'):
                nicName = re.search(r'Slave Interface: (\S+)', line).group(1)
                bond_info['slaves'].append(nicName)
    
        return bond_info
    
    def get_bonds(self):
        bonds = []
        try:
            if not os.path.exists(BOND_INFO_DIR):
                return bonds
            interfaces = [f for f in os.listdir(BOND_INFO_DIR) if os.path.isfile(os.path.join(BOND_INFO_DIR, f))]
            for interface in interfaces:
                bond = {}
                bond = self.parse_bonding_info(os.path.join(BOND_INFO_DIR, interface))
                bond.update(self.parse_network_config(interface))
                bonds.append(bond)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("get_bonds exception: %s" % e)
        return bonds    

    def config_bond(self, bond_info, ip_list, gate_info, remove_slaves, new_flag=True):
        # 判断如果bond名称为空则报错返回
        bond_name = bond_info["dev"]
        if not bond_name:
            return get_error_result("MessageError")
        
        # 如果网卡已经用于双机绑定的，也不能修改，否则绑定就失效了
        clusterNode = ClusterNode.objects.first()
        if clusterNode:
            nodeNic = clusterNode.local_nic if clusterNode.local_nic else find_interface_for_ip(clusterNode.local_ip)
            if nodeNic in bond_info["slaves"]:
                return get_error_result("NicAlreadyUsedInDoubleControl")
                    
        # bonding模块加载
        # 设置参数max_bonds=0是因为max_bonds的缺省默认值为1
        # 这会导致模块在/sys/class/net/bonding_masters中默认创建一个bond0（无任何slave）
        if not FileOp(constants.BOND_MASTERS).exist_file():
            logger.info('modprobe bonding max_bonds=0')
            self._run_cmd("modprobe bonding max_bonds=0")

        # 备份要修改的文件，以便出现异常时回滚
        # self._backup(bond_info["dev"], *bond_info["slaves"], *remove_slaves)

        try:
            if not os.path.exists(self.file_path % bond_name):                
                # 新增bond网卡配置文件
                if bond_info["mode"] == 0:
                    mode = 'balance-rr'
                elif bond_info["mode"] == 1:
                    mode = 'active-backup'
                elif bond_info["mode"] == 6:
                    mode = 'adaptive load'
            
                 #添加网卡bond配置
                cmd = 'nmcli connection add type bond con-name '+bond_name+' ifname '+bond_name+' bond.options \"mode='+mode+'\"'
                (status, output) = cmdutils.run_cmd(cmd)
                if status != 0:
                    logger.error("Add bond disposition error!!!!")
                    ret = get_error_result("ConfigBondError")
                    return ret 
                
                #绑定网卡到bond卡
                for item in bond_info["slaves"]:
                    cmd = 'nmcli connection add type ethernet slave-type bond con-name {}-{} ifname {} master {}'.format(bond_name, item, item, bond_name)
                    (status, output) = cmdutils.run_cmd(cmd)
                    if status != 0:
                        logger.error("Bind a NIC to bond error!!!")
                        ret = get_error_result("ConfigBondError")
                        return ret 
                    
                    #去掉.nmconnection使重启网络的时候不加载该文件
                    oldname = self.bond_path + item + '.nmconnection'
                    os.rename(oldname,self.bond_path + item)
           

            # 给bond网卡配IP
            if ip_list:
                for index, ip_info in enumerate(ip_list):
                    if 'netmask' in ip_info:
                        cidr = self.mask_to_cidr(ip_info['netmask'])
                        ip = ip_info['ip'] + '/' + str(cidr)
                    else:
                        ip = ip_info['ip']
                    

                    cmd = 'nmcli connection modify '+bond_name+' ipv4.addresses ' + ip
                    (status, output) = cmdutils.run_cmd(cmd)
                    if status != 0:
                        logger.error("bond Configure ip address error!!!")
                        ret = get_error_result("ConfigBondError")
                        return ret 
                    
                    
                    
            # 给bond网卡配网关 DNS
            if gate_info:
                if gate_info.get('gateway'):
                    cmd = 'nmcli connection modify '+bond_name+' ipv4.gateway '+gate_info['gateway']
                    (status, output) = cmdutils.run_cmd(cmd)
                    if status != 0:
                        logger.error("bond Configure gateway error!!!")
                        ret = get_error_result("ConfigBondError")
                        return ret 
                    
                dns1 = ''
                dns2 = ''
                if gate_info.get('dns1'):
                    dns1 = gate_info['dns1']
                if gate_info.get('dns2'):
                    dns2 = gate_info['dns2']
                        
                if dns1 != '' and dns2 != '':
                    dns = '\'' + dns1 + ',' + dns2 + '\''
                elif dns1 != '':
                    dns = dns1
                elif dns2 != '':
                    dns = dns2
                else:
                    dns = ''
                    

                if dns != '':
                    cmd = 'nmcli connection modify '+bond_name+' ipv4.dns '+dns
                    (status, output) = cmdutils.run_cmd(cmd)
                    if status != 0:
                        logger.error("bond Configure dns error!!!")
                        ret = get_error_result("ConfigBondError")
                        return ret 
                    
            # 需要重启网络服务，否则bond不能生效
            (status, output) = cmdutils.run_cmd("systemctl restart NetworkManager")
            if status != 0:
                logger.error("Failed to restart network!!!")
                ret = get_error_result("RestartNetworkError")
                return ret
                    

            # 启用bond网卡
            (status, output) = cmdutils.run_cmd("nmcli connection up "+bond_name)
            if status != 0:
                logger.error("Failed to restart network!!!")
                ret = get_error_result("RestartNetworkError")
                return ret
            
            #启用bond绑定的接口
            for item in bond_info["slaves"]:
                up_cmd = 'nmcli connection up {}-{}'.format(bond_name,item)
                (status, output) = cmdutils.run_cmd(up_cmd)
                if status != 0:
                    logger.error("Failed to restart network!!!")
                    ret = get_error_result("RestartNetworkError")
                    return ret 
            

            resp = {
                "bond_nic_info": self._get_network_info(bond_info['dev'])
            }

            # self._clear_backup()
            return get_error_result("Success", resp)
        except Exception as e:
            logger.error("config_bond Exception: %s" % str(e), exc_info=True)
            self.unbond(bond_info["dev"],bond_info["slaves"])
            self._rollback(bond_info["dev"], new_flag)
            return get_error_result("ConfigBondError")

    def unbond(self, bond_name, slaves):
        try:
            self._run_cmd("ip link del dev %s" % bond_name)

            #删除bond网卡配置
            (status, output) = cmdutils.run_cmd("nmcli connection delete "+ bond_name)
            if status != 0:
                logger.error("Delete bond error!!!")
                ret = get_error_result("UnBondError")
                return ret  
            
            #删除bond绑定的相关网卡配置
            for item in slaves:
                if isinstance(item,str):
                    name = item
                else:
                    name = item["nic"]

                filename = 'nmcli connection delete '+bond_name + '-' + name
                (status, output) = cmdutils.run_cmd(filename)
                if status != 0:
                    logger.error("Delete bond to nic error!!!")
                    ret = get_error_result("UnBondError")
                    return ret  
                
                #文件名加上.nmconnection
                oldname = self.bond_path + name 
                os.rename(oldname,self.bond_path + name+ '.nmconnection')

                #重新读取配置文件
                (status, output) = cmdutils.run_cmd("systemctl restart NetworkManager")
                if status != 0:
                    logger.error("Failed to restart network!!!")
                    ret = get_error_result("RestartNetworkError")
                    return ret   

                #启动解除绑定的网卡
                up_cmd = 'nmcli connection up '+ name
                (status, output) = cmdutils.run_cmd(up_cmd)
                if status != 0:
                    logger.error("Failed to restart network!!!")
                    ret = get_error_result("RestartNetworkError")
                    return ret          
                 

            return get_error_result("Success")
        except Exception as e:
            logger.error("config_bond Exception: %s" % str(e), exc_info=True)
            self.unbond(bond_name,slaves)
            self._rollback(bond_name, new_flag=False)
            return get_error_result("UnBondError")

    def _get_network_info(self, nic_name):
        """获取bond网卡的mac speed status 参照接口/monitor/network"""
        try:
            nic_addrs = psutil.net_if_addrs()
            nic_mac = ""
            nic_speed = 0
            for info in nic_addrs[nic_name]:
                if str(info.family) == "AddressFamily.AF_PACKET":
                    nic_mac = info.address

            try:
                ret = cmdutils.run_cmd('ethtool %s|grep "Speed"' % nic_name)[1].split('\n')[-1]
                speed = re.sub("\D", "", ret)
                if speed:
                    nic_speed = int(speed)
            except Exception as e:
                logger.error("nic_speed Exception: %s" % str(e), exc_info=True)
                nic_speed = 0

            try:
                # 网卡是否插网线
                nic_stat = bool(int(open('/sys/class/net/{}/carrier'.format(nic_name), 'r').readline()[0]))
            except Exception as e:
                logger.error("nic_stat Exception: %s" % str(e), exc_info=True)
                nic_stat = False

            resp = {
                "nic": nic_name,
                'mac': nic_mac,
                'speed': nic_speed,
                'status': 2 if nic_stat else 1
            }
            logger.info("get_network_info resp: %s" % resp)

        except Exception as e:
            logger.error("get_network_info Exception: %s" % str(e), exc_info=True)
            resp = dict()

        return resp
    
    def cidr_to_mask(self,cidr):  
        # 检查CIDR是否是一个有效的数字  
        if not isinstance(cidr, int) or cidr < 0 or cidr > 32:  
            raise ValueError("CIDR must be an integer between 0 and 32")  
    
        # 创建一个长度为32的二进制字符串，所有位都设置为1  
        mask = '1' * 32  
    
        # 将CIDR后面的位设置为0  
        mask = mask[:cidr] + '0' * (32 - cidr)  
    
        # 将二进制字符串转换为四个字节的子网掩码  
        octets = [mask[i:i+8] for i in range(0, 32, 8)]  
        decimal_octets = [str(int(octet, 2)) for octet in octets]  
    
        # 将四个字节合并为一个点分十进制的字符串  
        return '.'.join(decimal_octets)  
    
    def mask_to_cidr(self,mask):  
        prefix_length = sum(bin(int(byte)).count('1') for byte in mask.split('.'))  
        return prefix_length  

    def _run_cmd(self, cmd_str):
        code, out = cmdutils.run_cmd(cmd_str)
        if code != 0:
            if "already uses address" in out:
                mac = re.search(self.mac_regex, out).group(0)
                ip = re.search(self.ip_regex, out).group(0)
                return get_error_result("IPUsedByOtherHost", mac=mac, ip=ip)
        return None

    def _remove_file(self, file_path, log_str):
        try:
            os.remove(file_path)
            logger.info("remove %s: %s" % (log_str, file_path))
        except Exception as e:
            logger.error("remove %s: %s failed: %s" % (log_str, file_path, str(e)))

    def _backup(self, *args):
        if not os.path.exists(self.backup_dir):
            os.mkdir(self.backup_dir)
        for filename in args:
            if os.path.exists(self.file_path % filename):
                shutil.copy2(self.file_path % filename, os.path.join(self.backup_dir, filename))
        logger.info("_backup bond ifcfg-file finished")

    def _clear_backup(self):
        logger.info("start _clear_backup")
        try:
            for filename in os.listdir(self.backup_dir):
                os.remove(os.path.join(self.backup_dir, filename))
        except Exception as e:
            logger.error('_clear_backup error: %s ' % str(e))
            cmdutils.run_cmd("rm -f %s" % self.backup_dir)
            os.mkdir(self.backup_dir)
        logger.info("_clear_backup finished")

    def _rollback(self, bond_name, new_flag=True):
        logger.info("start _rollback")
        if new_flag:
            # 新增bond回滚需要删除bond的master身份和ifcfg文件
            cmdutils.run_cmd("echo -%s > %s" % (bond_name, constants.BOND_MASTERS))
            try:
                os.remove(self.file_path % bond_name)
                logger.info("remove file: %s" % (self.file_path % bond_name))
            except Exception as e:
                logger.error('_rollback error: %s ' % str(e))

        for filename in os.listdir(self.backup_dir):
            # 新增bond时不会备份bond的ifcfg文件，所以还原时自然也不应该存在bond的ifcfg文件，万一存在了，也不要还原它
            # 编辑、删除bond时需要还原bond的ifcfg文件
            if new_flag and filename == bond_name:
                continue
            try:
                shutil.copy2(os.path.join(self.backup_dir, filename), self.file_path % filename)
                cmdutils.run_cmd("ifconfig %s down" % filename)
                cmdutils.run_cmd("ifconfig %s up" % filename)
            except Exception as e:
                logger.error('_rollback error: %s ' % str(e))
                continue
        logger.info("_rollback finished")
        self._clear_backup()

    def add_ip_info(self, data):
        """
        {
            "name": "eth0",
            "ip_infos"[
                {
                    "ip": "172.16.1.31",
                    "netmask": "255.255.255.0"
                },
                ...
            ],
            "gate_info": {
                "gateway": "172.16.1.254",
                "dns1": "8.8.8.8",
                "dns2": "114.114.114.114"
            },
            "net_info": {
                "network_id": "",
                "physical_interface": ""
            }
        }
        :return:
        """
        try:
            nic_name = data.get("name")
            virtual_net_device = os.listdir('/sys/devices/virtual/net/')
            nic_addrs = psutil.net_if_addrs()
            physical_net_device = [dev for dev in nic_addrs.keys() if dev not in virtual_net_device]
            if nic_name.split(':')[0] not in physical_net_device:
                logger.error("add nic %s ip, not physical nic" % nic_name)
                return get_error_result("NotPhysicalNICError")

            resp = dict()
            resp['data'] = {}
            utc = int((dt.datetime.utcnow() - dt.datetime.utcfromtimestamp(0)).total_seconds())
            resp['data']['utc'] = utc
            nic_ifcfg = "/etc/sysconfig/network-scripts/ifcfg-%s" % nic_name
            nic_content = [
                "NAME=%s" % nic_name,
                "DEVICE=%s" % nic_name,
                "TYPE=Ethernet",
                "ONBOOT=yes",
                # "DEFROUTE=no",
                "NM_CONTROLLED=no",
                "BOOTPROTO=%s" % ("static" if data.get('ip_infos') else "none")
            ]
            logger.info("the nic content:%s" % nic_content)
            # 更新IP信息
            for index, info in enumerate(data['ip_infos']):
                nic_content.append("IPADDR%s=%s" % (index, info['ip']))
                nic_content.append("NETMASK%s=%s" % (index, info['netmask']))
            if data.get('gate_info'):
                if data['gate_info'].get('gateway'):
                    nic_content.append("GATEWAY=%s" % data['gate_info']['gateway'])
                if data['gate_info'].get('dns1'):
                    nic_content.append("DNS1=%s" % data['gate_info']['dns1'])
                if data['gate_info'].get('dns2'):
                    nic_content.append("DNS2=%s" % data['gate_info']['dns2'])
            self.update_conf(nic_ifcfg, nic_content)
            # 如果是flat网络，则需要将网卡信息配置到网桥上
            net_info = data.get('net_info')
            cmdutils.run_cmd("ifconfig %s down" % nic_name)
            cmdutils.run_cmd("ifconfig %s up" % nic_name)
            logger.info("set nic %s ip success" % nic_name)
            resp["data"] = {
                "name": nic_name
            }
            return resp
        except Exception as e:
            logger.error(e)
            raise e
