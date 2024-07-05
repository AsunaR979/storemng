import logging
import re
import os
import traceback
import psutil
import shutil
import datetime as dt
from web_manage.cluster.models import ClusterNode
from web_manage.common.utils import FileOp, find_interface_for_ip
from web_manage.common import constants, cmdutils
from web_manage.common.errcode import get_error_result
from web_manage.common.constants import BOND_INFO_DIR

logger = logging.getLogger(__name__)


class BondManager(object):

    def __init__(self):
        self.base_dir = "/etc/sysconfig/network-scripts/"
        self.file_path = "/etc/sysconfig/network-scripts/ifcfg-%s"
        self.common_content = [
            "TYPE=Ethernet",
            "ONBOOT=yes",
            "NM_CONTROLLED=no"
        ]
        self.unbond_common_content = [
            "TYPE=Ethernet",
            "ONBOOT=yes",
        ]
        self.backup_dir = os.path.join(self.base_dir, 'bond_backup')
        if not os.path.exists(self.backup_dir):
            os.mkdir(self.backup_dir)
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
        config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface_name}"
        if not os.path.exists(config_file):
            return {}
    
        with open(config_file, 'r') as file:
            lines = file.readlines()
    
        network_config = {
            'ip': '',
            'netmask': '',
            'gateway': '',
            'dns1': '',
            'dns2': ''
        }
    
        for line in lines:
            if line.startswith('IPADDR0='):
                network_config['ip'] = line.split('=')[1].strip()
            elif line.startswith('NETMASK0='):
                network_config['netmask'] = line.split('=')[1].strip()
            elif line.startswith('GATEWAY='):
                network_config['gateway'] = line.split('=')[1].strip()
            elif line.startswith('DNS1='):
                network_config['dns1'] = line.split('=')[1].strip()
            elif line.startswith('DNS2='):
                network_config['dns2'] = line.split('=')[1].strip()
    
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

        #判断指定ip是否被使用,ip冲突会导致bond失败网络不可用
        if ip_list:
            for index, ip_info in enumerate(ip_list):       
                command = f"ping -c 3 {ip_info['ip']}"
                (status, output) = cmdutils.run_cmd(command)
                if status == 0:
                    logger.error(f"Ping to {ip_info['ip']} failed.")
                    resp = get_error_result("IpIsBeingUsed")
                    return resp
                else:
                    logger.debug(f"Ping to {ip_info['ip']} successful.")
                    


        # 判断如果bond名称为空则报错返回
        if not bond_info["dev"]:
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
        self._backup(bond_info["dev"], *bond_info["slaves"], *remove_slaves)

        try:
            # 编辑bond时允许变更被绑定网卡，可能出现slaves减少的情况，需要更新减少网卡的配置文件，并移除slave身份
            if remove_slaves:
                for free_slave in remove_slaves:
                    ifconf = self.file_path % free_slave
                    self._remove_file(ifconf, 'free slave')
                    recover_content = [
                        "NAME=%s" % free_slave,
                        "DEVICE=%s" % free_slave,
                        "BOOTPROTO=none",
                    ]
                    recover_content.extend(self.common_content)
                    self.update_conf(ifconf, recover_content)

                    # # 从/sys/devices/virtual/net/bond0/bonding/slaves移除要删除的slave名称，否则slave身份仍会存在
                    # self._run_cmd("echo -%s > %s" % (free_slave, constants.BOND_SLAVES % bond_info['dev']))
                    self._run_cmd("ip link set dev %s nomaster" % free_slave)

                    # 启用已还原的物理网卡
                    self._run_cmd("ifconfig %s up" % free_slave)

            # 更新slave网卡配置文件
            for slave in bond_info["slaves"]:
                ifconf = self.file_path % slave
                self._remove_file(ifconf, 'slave')
                slave_content = [
                    "NAME=%s" % slave,
                    "DEVICE=%s" % slave,
                    "BOOTPROTO=none",
                    "MASTER=%s" % bond_info['dev'],
                    "SLAVE=yes",
                ]
                slave_content.extend(self.common_content)
                self.update_conf(ifconf, slave_content)
                self._run_cmd("ifconfig %s down" % slave)

            # 新增bond网卡配置文件
            bond_conf = self.file_path % bond_info['dev']
            bond_content = [
                "NAME=%s" % bond_info['dev'],
                "DEVICE=%s" % bond_info['dev'],
                "TYPE=bond",
                "BONDING_MASTER=yes",
                'BONDING_OPTS="mode=%s miimon=100"' % bond_info['mode'],
                "BOOTPROTO=%s" % ("none" if 0 == len(ip_list) else "static"),
            ]
            bond_content.extend(self.common_content[1:])

            # 给bond网卡配IP
            if ip_list:
                for index, ip_info in enumerate(ip_list):
                    bond_content.append(
                        "IPADDR%s=%s" % (index, ip_info['ip'])
                    )
                    bond_content.append(
                        "NETMASK%s=%s" % (index, ip_info['netmask'])
                    )
            # 给bond网卡配网关、DNS
            if gate_info:
                if gate_info.get('gateway'):
                    bond_content.append("GATEWAY=%s" % gate_info['gateway'])
                if gate_info.get('dns1'):
                    bond_content.append("DNS1=%s" % gate_info['dns1'])
                if gate_info.get('dns2'):
                    bond_content.append("DNS2=%s" % gate_info['dns2'])
            self.update_conf(bond_conf, bond_content)

            # 需要重启网络服务，否则bond不能生效
            (status, output) = cmdutils.run_cmd("systemctl restart network")
            if status != 0:
                logger.error("Failed to restart network!!!")
                ret = get_error_result("RestartNetworkError")
                return ret
            
            if not new_flag:
                # 如果是编辑bond，需先关闭bond网卡再启用
                self._run_cmd("ifconfig %s down" % bond_info["dev"])

            # 启用bond网卡
            ifup_ret = self._run_cmd("ifconfig %s up" % bond_info["dev"])
            # IP冲突导致网卡无此IP
            if ifup_ret:
                self._rollback(bond_info["dev"], new_flag)
                return ifup_ret

            resp = {
                "bond_nic_info": self._get_network_info(bond_info['dev'])
            }

            self._clear_backup()
            return get_error_result("Success", resp)
        except Exception as e:
            logger.error("config_bond Exception: %s" % str(e), exc_info=True)
            self._rollback(bond_info["dev"], new_flag)
            return get_error_result("ConfigBondError")

    def unbond(self, bond_name, slaves):
        try:
            self._run_cmd("ip link del dev %s" % bond_name)

            # 备份要修改的文件，以便出现异常时回滚
            self._backup(bond_name, *[_d["nic"] for _d in slaves])

            # 删除bond网卡配置文件
            bond_ifconf = self.file_path % bond_name
            self._remove_file(bond_ifconf, 'bond')

            for slave in slaves:
                # 更新slave网卡配置文件
                slave_content = [
                    "NAME=%s" % slave['nic'],
                    "DEVICE=%s" % slave['nic'],
                    "BOOTPROTO=%s" % ("static" if slave.get('ip_list') else "none"),
                ]
                slave_content.extend(self.unbond_common_content)
                ifconf = self.file_path % slave['nic']
                self._remove_file(ifconf, 'unbond slave')

                # 给slave网卡配IP
                ip_list = slave.get("ip_list", [])
                if ip_list:
                    for index, ip_info in enumerate(ip_list):
                        slave_content.append(
                            "IPADDR%s=%s" % (index, ip_info['ip'])
                        )
                        slave_content.append(
                            "NETMASK%s=%s" % (index, ip_info['netmask'])
                        )
                    # 给slave网卡配网关、DNS
                    if ip_list[0].get('gateway'):
                        slave_content.append("GATEWAY=%s" % ip_list[0]['gateway'])
                    if ip_list[0].get('dns1'):
                        slave_content.append("DNS1=%s" % ip_list[0]['dns1'])
                    if ip_list[0].get('dns2'):
                        slave_content.append("DNS2=%s" % ip_list[0]['dns2'])
                self.update_conf(ifconf, slave_content)
                # 需要重启网络服务，否则bond不能生效
                (status, output) = cmdutils.run_cmd("systemctl restart network")
                if status != 0:
                    logger.error("Failed to restart network!!!")
                    ret = get_error_result("RestartNetworkError")
                    return ret                
                self._run_cmd("ifconfig %s down" % slave['nic'])
                ifup_ret = self._run_cmd("ifconfig %s up" % slave['nic'])
                # IP冲突导致网卡无此IP
                if ifup_ret:
                    self._rollback(bond_name, new_flag=False)
                    return ifup_ret

            # # 从/sys/class/net/bonding_masters移除要删除的bond名称，否则该bond仍会存在
            # self._run_cmd("echo -%s > %s" % (bond_name, constants.BOND_MASTERS))
            self._clear_backup()
            return get_error_result("Success")
        except Exception as e:
            logger.error("config_bond Exception: %s" % str(e), exc_info=True)
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
