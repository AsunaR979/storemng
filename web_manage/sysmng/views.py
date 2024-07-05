import glob
import operator
import shutil
import string
import logging
import base64
import copy
import threading
from django.db import connection
import psutil
from enum import Enum
from datetime import datetime
from pytz import timezone
import pytz
from rest_framework.decorators import action
from storesys.settings import VERSION, ROOT_DIR, PRIMARY_DIR_NAME, DATABASE_FILE_NAME
from web_manage.cluster.keepalived.views import read_config_file_to_dict
from web_manage.cluster.models import ClusterNode
from web_manage.common.constants import COPY_LV_CONFIG_PATH, DOUBLE_CONTROL_CONFIG_PATH, HEARTBEAT_CONFIG_FILE_PATH, LOCALTIME_LINK_FILE, MONITOR_SERVICES, NFS_CONFIG_FILE, NTP_CONFIG_FILE, TGTD_CONFIG_FILE_PATH, TIMEZONE_PATH

from web_manage.common.http import peer_post
from web_manage.common.utils import JSONResponse, WebPagination, Authentication, Permission, create_md5, find_interface_for_ip, \
    get_error_result, is_include_in_arr
from web_manage.common.log import insert_operation_log

from rest_framework.views import APIView
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.shortcuts import HttpResponse
#from django.utils import timezone
import hashlib
import time
from rest_framework import status
from django.db.models import Q

from django.core.cache import cache
from django.http import Http404, HttpResponseServerError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import subprocess, re
from web_manage.common.cmdutils import run_cmd
import netifaces as ni
import configparser
import os
import traceback
from .bond_mgr import BondManager


logger = logging.getLogger(__name__)


class HostmngCmd(Enum):
    GetTimeInfo = "getTimeInfo"
    SetDateTimeZone = "setTime"
    Restart = "restart"
    Shutdown = "shutdown"
    ShudownDoubleControl = "shudownDoubleControl"


class HostmngView(APIView):
    """host manage"""
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in HostmngCmd.__members__.values()]),
            'date_time': openapi.Schema(type=openapi.TYPE_STRING),
            'timezone': openapi.Schema(type=openapi.TYPE_STRING),
            'ifNetTimeSync': openapi.Schema(type=openapi.TYPE_STRING),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))
    def post(self, request, *args, **kwargs):
        ret = get_error_result("Success")
        command = request.data.get("command")
        remote_ip = request.META.get('HTTP_X_FORWARDED_FOR') if request.META.get(
            'HTTP_X_FORWARDED_FOR') else request.META.get("REMOTE_ADDR")
        user_info = {
            "id": 1,
            "user_name": 'admin',
            "user_ip": remote_ip
        }
        try:

            logger.info("user command: %s , ip %s" % (command, remote_ip))
            msg = "在ip: %s 执行 %s" % (remote_ip, command)
            insert_operation_log(msg, ret["msg"], user_info)
            if command == "restart":
                ret = self.restart_machine()
            elif command == "shutdown":
                ret = self.turn_off_machine()
            elif command == "shudownDoubleControl":
                ret = self.turn_off_double_machine()
            elif command == "getTimeInfo":
                ret = self.get_time_info()
            elif command == "setTime":
                ret = self.set_time(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def restart_machine(self):
        resp = get_error_result("Success")
        try:
            # 将缓冲数据写入磁盘
            syncCmd = "sync"
            (syncStatus, syncOutput) = run_cmd(syncCmd)
            if syncStatus != 0:
                logger.error(f"Failed to execute sync (reboot) ===> {syncOutput}!!!")

            # 重启机器（延时3秒）：不等待，可以直接返回
            rebootCmd = "shutdown -r now -t 3"
            subprocess.Popen(rebootCmd, shell=True)

            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("restart_machine exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp

    def turn_off_machine(self):
        resp = get_error_result("Success")
        try:
            # 将缓冲数据写入磁盘
            syncCmd = "sync"
            (syncStatus, syncOutput) = run_cmd(syncCmd)
            if syncStatus != 0:
                logger.error(f"Failed to execute sync (shutdown) ===> {syncOutput}!!!")
            # 关闭服务
            stopServiceCmd = "systemctl stop smb nfs vsftpd tgtd iscsid keepalived"
            (stopServiceStatus, stopServiceOutput) = run_cmd(stopServiceCmd)
            if stopServiceStatus != 0:
                logger.error(f"Failed to stop services ===> {stopServiceOutput}!!!")
            # 关闭机器（延时20秒）：不等待，可以直接返回
            shutdownCmd = "shutdown -h now -t 20"
            subprocess.Popen(shutdownCmd, shell=True)
            # 接口还可以正常返回
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("turn_off_machine exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp
        
    def turn_off_double_machine(self):
        resp = get_error_result("Success")
        try:
            # 1、关闭本地和远程端的心跳服务，防止发生故障迁移
            stopCmd = "systemctl stop keepalived"
            (stopCmdStatus, stopCmdOutput) = run_cmd(stopCmd)
            if stopCmdStatus != 0:
                logger.error(f"Failed to stop keepalived: {stopCmdOutput}!!!")
            # 发起http请求获取对端机器的关闭keepalived
            reqData = {
                "command": "stop",
                "requestEnd": "backend",
                "service": "keepalived"
            }
            remoteResp = peer_post("/sysmng/srvmng/operate/", reqData)
            if remoteResp.get("code") != 0:
                logger.error(f"Peer compute failed to stop keepalived !!!")

            # 2、本地执行断开所有的复制逻辑卷连接
            res_files = glob.glob(os.path.join(COPY_LV_CONFIG_PATH, '*.res'))
            resNames = [os.path.splitext(os.path.basename(file_path))[0] for file_path in res_files] 
            for resName in resNames:
                run_cmd(f"drbdadm disconnect {resName}")
                logger.info(f'execute disconnect copyLv {resName}')

            # 将缓冲数据写入磁盘
            syncCmd = "sync"
            (syncStatus, syncOutput) = run_cmd(syncCmd)
            if syncStatus != 0:
                logger.error(f"Failed to execute sync (shutdown) ===> {syncOutput}!!!")

            # 关闭NAS、SAN服务
            stopServiceCmd = "systemctl stop smb nfs vsftpd tgtd iscsid"
            (stopServiceStatus, stopServiceOutput) = run_cmd(stopServiceCmd)
            if stopServiceStatus != 0:
                logger.error(f"Failed to stop services ===> {stopServiceOutput}!!!")

            # 发起http请求对端进行关机
            reqData = {
                "command": "shutdown",
                "requestEnd": "backend"
            }
            remoteResp = peer_post("/sysmng/hostmng/operate/", reqData)
            if remoteResp.get("code") != 0:
                logger.error(f"Peer compute failed to shutdown !!!")

            # 关闭机器(延时20秒)：不等待，可以直接返回
            shutdownCmd = "shutdown -h now -t 20"
            subprocess.Popen(shutdownCmd, shell=True)

            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("turn_off_machine exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp        

    def get_time_info(self):
        resp = get_error_result("Success")
        # 构建时间信息字典
        time_info = {}
        try:
            # 获取当前系统的时间信息
            system_timezone = self.get_system_timezone()
            ifNetTimeSync = self.get_ntpserve_status()
            time_info['timezone'] = system_timezone
            time_info['ifNetTimeSync'] = ifNetTimeSync
            #date_time = ' '.join(dateTimeArray[5].split('=')[1].split()[1:3])
            # 获取当前系统的日期和时间
            current_time = datetime.now()
            # 将当前时区时间转换为目标时区时间，格式化日期和时间字符串，存放到time_info
            
            target_timezone = time_info['timezone']
            time_info['date_time'] = current_time.astimezone(timezone(target_timezone)).strftime("%Y-%m-%d %H:%M:%S")
            # 获取当前系统下的所有NTP服务器
            getNtpServersCmd = "cat /etc/chrony.conf | grep -w server | grep -v '#' | awk '{print $2}'"
            (status, getNtpServersOutput) = run_cmd(getNtpServersCmd)
            if is_include_in_arr(getNtpServersOutput, ['No such file or directory', '没有那个文件或目录']):
                logger.error(f"Failed to get NTP servers ===> {getNtpServersOutput}!!!")
                resp = get_error_result("GetNtpServersError")
                return resp
            # NTP服务器存放到time_info
            time_info['ntp_servers'] = getNtpServersOutput.strip().splitlines()

            resp = get_error_result("Success", time_info)
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("get_time_info exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp
        
    def read_chrony_conf(self, filename):
        with open(filename, 'r') as file:
            content = file.readlines()
        return content

    def write_chrony_conf(self, filename, content):
        with open(filename, 'w') as file:
            file.writelines(content)

    def add_server_to_conf(self, filename, server):
        content = self.read_chrony_conf(filename)
        server_line = f"server {server} iburst\n"
        # 把server配置直接追加到文件末尾
        content.append(server_line)
        self.write_chrony_conf(filename, content)

    def remove_all_servers_from_conf(self, filename):
        content = self.read_chrony_conf(filename)
        newContent = []
        for i, line in enumerate(content):
            # 去掉所有server开头的行
            if line.startswith('server '):
                continue
            else:
                newContent.append(line)
        self.write_chrony_conf(filename, newContent)

    def set_time(self, request, args, kwargs):
        resp = get_error_result("Success")
        ifNetTimeSync = request.data.get('ifNetTimeSync')
        date_time = request.data.get('date_time')
        timeZone = request.data.get('timezone')
        ntp_servers = request.data.get('ntp_servers')
        try:
            # 设置时区
            TIMEZONE = TIMEZONE_PATH + timeZone
            os.system(f'cp {LOCALTIME_LINK_FILE} {LOCALTIME_LINK_FILE}.bak')
            setTimezoneCmd = ('ln -sf {} {}'.format(TIMEZONE, LOCALTIME_LINK_FILE))

            (status, setTimezoneOutput) = run_cmd(setTimezoneCmd)
            if status != 0:
                if 'Invalid time zone' in setTimezoneOutput:
                    logger.error(f"Invalid time zone ===> {setTimezoneOutput}!!!")
                    os.system(f'mv {LOCALTIME_LINK_FILE}.bak {LOCALTIME_LINK_FILE}')
                    resp = get_error_result("InvalidTimezone")
                    return resp
                else:
                    logger.error(f"Failed to set time zone ===> {setTimezoneOutput}!!!")
                    os.system(f'mv {LOCALTIME_LINK_FILE}.bak {LOCALTIME_LINK_FILE}')
                    resp = get_error_result("SetTimezoneError")
                    return resp
            
            # 设置NTP服务器地址或者域名
            if not ntp_servers:
                logger.error(f"ntp_servers cant't be null !!!")
                resp = get_error_result("MessageError")
                return resp
            # 先备份配置文件
            shutil.copy2(NTP_CONFIG_FILE, f'{NTP_CONFIG_FILE}.bak')
            # 删除所有ntp的服务器设置信息
            self.remove_all_servers_from_conf(NTP_CONFIG_FILE)
            for ntpServer in ntp_servers:
                self.add_server_to_conf(NTP_CONFIG_FILE, ntpServer)
            # 启用NTP
            if ifNetTimeSync == "true":
                # 禁用网络时间同步
                stopNtpCmd = 'systemctl stop chronyd'
                (stopNtpStatus, stopNtpOutput) = run_cmd(stopNtpCmd)
                if stopNtpStatus != 0:
                    logger.error("Failed to stop NTP!!!")
                    resp = get_error_result("StopNtpError")
                    return resp
                # 同步系统时钟至硬件时钟
                syncHwClockCmd = "hwclock -w"
                (syncHwClockStatus, syncHwClockOutput) = run_cmd(syncHwClockCmd)
                if syncHwClockStatus != 0:
                    logger.error("Failed to synchronize hardware clock!!!")
                    resp = get_error_result("SyncHwClockError")
                    return resp
                # 启用网络时间同步
                startNtpCmd = "systemctl start chronyd"
                (startNtpStatus, startNtpOutput) = run_cmd(startNtpCmd)
                if startNtpStatus != 0:
                    logger.error("Failed to start NTP!!!")
                    resp = get_error_result("StartNtpError")
                    return resp
            # 禁用NTP
            else:
                # 禁用网络时间同步
                stopNtpCmd = "systemctl stop chronyd"
                (stopNtpStatus, stopNtpOutput) = run_cmd(stopNtpCmd)
                if stopNtpStatus != 0:
                    logger.error("Failed to stop NTP!!!")
                    resp = get_error_result("StopNtpError")
                    return resp
                # 设置日期和时间
                setDateTimeCmd = "hwclock --set --date='{}'".format(date_time)
                (status, setDateTimeOutput) = run_cmd(setDateTimeCmd)
                if status != 0:
                    logger.error("Failed to set date and time!!!")
                    resp = get_error_result("SetDateTimeError")
                    return resp
                os.system('hwclock --hctosys')
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("set_time exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp

    def get_system_timezone(self):
        localtime_path = os.path.realpath('/etc/localtime')
        timezone = None
        
        # 假设时区文件位于/usr/share/zoneinfo/下
        for root, dirs, files in os.walk(TIMEZONE_PATH):
            if localtime_path.startswith(root):
                # 提取相对路径并作为时区
                relative_path = os.path.relpath(localtime_path, root)
                break

        return relative_path  
    
    def get_ntpserve_status(self):
        cmd = 'systemctl is-active chronyd'
        (status, output) = subprocess.getstatusoutput(cmd)
        if output in 'active':
            return True
        else:
            return False
    


class NetmngCmd(Enum):
    GetHostname = "getHostname"
    SetHostname = "setHostname"
    GetAllNicsInfo = "getAllNicsInfo"
    SetNicInfo = "setNicInfo"
    NewBond = "newBond"
    GetBonds = "getBonds"
    EditBond = "editBond"
    UnBond = "unBond"
    GetRouteInfo = "getRouteInfo"
    AddORdelRoute = "addORdelRoute"


class NetmngView(APIView):
    """network manage"""

    def get_network_interfaces(self):
        network_info = []
        try:
            interfaces = ni.interfaces()
            for interface in interfaces:
                interface_info = {}

                # 检查是否启用DHCP
                dhcp_enabled = False
                (status, output) = run_cmd("ip addr show " + interface)
                # 过滤已经创建过bond的网卡
                if 'SLAVE' in output:
                    continue
                interface_info['is_bond'] = False
                if 'MASTER' in output:
                    interface_info['is_bond'] = True
                if 'dynamic' in output:
                    dhcp_enabled = True
                interface_info['dhcp_enabled'] = dhcp_enabled

                # 获取网卡名
                interface_info['name'] = interface
                if interface == "lo":
                    continue

                #获取link状态
                interface_info['linkStatus'] = False
                (status, cmdOutput) = run_cmd(f"ethtool {interface} | grep \"Link detected\"")
                if status == 0 and "yes" in cmdOutput:
                    interface_info['linkStatus'] = True

                # 获取MAC地址
                mac = ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
                interface_info['mac'] = mac

                # 获取IP地址
                if ni.ifaddresses(interface).get(ni.AF_INET) is not None:
                    ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                    interface_info['ip'] = ip

                # 获取子网掩码
                if ni.ifaddresses(interface).get(ni.AF_INET) is not None:
                    netmask = ni.ifaddresses(interface)[
                        ni.AF_INET][0]['netmask']
                    interface_info['netmask'] = netmask

                # 获取DNS服务器
                dns_servers = []
                # 局限性：以下是类CentOS系统的网卡配置文件路径，其他系统可能有差异，后续完善
                file_path = '/etc/sysconfig/network-scripts/'
                file_name =  'ifcfg-' + interface
                
                # 判断网卡配置文件是否存在，可以过滤一些虚拟网卡
                if not os.path.exists(file_path + file_name):
                    continue

                with open(file_path + file_name, 'r') as file:
                    for line in file:
                        if line.startswith('DNS'):
                            dns_server = line.split('=')[1].strip()
                            dns_servers.append(dns_server)
                        # 获取网关
                        if line.startswith('GATEWAY'):
                            gateway = line.split('=')[1].strip()
                            interface_info['gateway'] = gateway

                if len(dns_servers) > 0:
                    dns1 = dns_servers[0]
                    interface_info['dns1'] = dns1
                if len(dns_servers) > 1:
                    dns2 = dns_servers[1]
                    interface_info['dns2'] = dns2

                network_info.append(interface_info)
        except Exception as e:
            logger.error("get_network_interfaces exception: %s" % e)
        return network_info

    def update_network_interface(self, interface_name, new_info):
        """
        # 指定要修改的网卡名称和要更新的属性值
        interface_name = 'ens35'
        new_info = {
            'IPADDR': '192.168.1.100',
            'NETMASK': '255.255.255.0',
            'GATEWAY': '192.168.1.1',
            'BOOTPROTO': 'none',  # 禁用 DHCP
            'DNS1': '8.8.8.8',
            'DNS2': '8.8.4.4'
        }
        new_info = {
            'IPADDR': '',  # 清空静态 IP 地址
            'NETMASK': '',  # 清空子网掩码
            'GATEWAY': '',  # 清空网关
            'BOOTPROTO': 'dhcp',  # 启用 DHCP
            'DNS1': '8.8.8.8',
            'DNS2': '8.8.4.4'
        }
        """
        try:
            # 构建网卡配置文件的路径
            config_file = f"/etc/sysconfig/network-scripts/ifcfg-{interface_name}"

            # 删除配置文件中的 PREFIX 字段，避免 NETMASK 设置失效
            grepCmd = "grep PREFIX %s" % (config_file)
            (status, grepCmd_output) = run_cmd(grepCmd)
            if status == 0:
                sedCmd = "sed -i '/PREFIX/d' %s" % (config_file)
                (status, sedCmd_output) = run_cmd(sedCmd)

            # 读取当前的网卡配置文件内容
            with open(config_file, "r") as file:
                lines = file.readlines()

            # 更新属性值
            for key, value in new_info.items():
                updated_line = f"{key.upper()}={value}\n"
                for i, line in enumerate(lines):
                    if line.startswith(key.upper()):
                        lines[i] = updated_line
                        break
                else:
                    lines.append(updated_line)

            # 将更新后的配置写回文件
            with open(config_file, "w") as file:
                file.writelines(lines)

            return True
        except Exception as e:
            logger.error("update_network_interface exception: %s" % e)
            return False

    # 获取路由信息
    def get_route_info(self):
        resp = get_error_result("Success")
        try:
            # 获取路由信息
            getRouteInfoCmd = "route -n | awk 'NR>2{print}' | sed 's/ \+/,/g'"
            (status, output) = run_cmd(getRouteInfoCmd)
            if is_include_in_arr(output, ['command not found', '未找到命令']):
                logger.error("Failed to get route information!!!")
                resp = get_error_result("GetRouteInfoError")
                return resp
            # 解析输出结果
            lines = output.strip().splitlines()
            # 构建路由信息列表
            route_info = []
            for line in lines:
                fields = [item.strip() for item in line.split(",")]
                dest = fields[0]
                gateway = fields[1]
                mask = fields[2]
                flags = fields[3]
                metric = fields[4]
                ref = fields[5]
                use = fields[6]
                iface = fields[7]
                isNormalRoute = self.retrieve_route_cfg('any', dest, gateway, mask, iface)
                default = not isNormalRoute
                route_info.append({
                    'dest': dest,
                    'gateway': gateway,
                    'mask': mask,
                    'flags': flags,
                    'metric': metric,
                    'ref': ref,
                    'use': use,
                    'iface': iface,
                    'default': default
                })
            resp = get_error_result("Success", route_info)
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("get_route_info exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp

    # 添加或删除路由
    def add_or_del_route(self, request, args, kwargs):
        resp = get_error_result("Success")
        operate = request.data.get('operate')
        dest = request.data.get('dest')
        gateway = request.data.get('gateway')
        mask = request.data.get('mask')
        iface = request.data.get('iface')
        try:
            # 检索路由配置信息
            isDefaultRoute = self.retrieve_route_cfg('del', dest, gateway, mask, iface)
            isNormalRoute = self.retrieve_route_cfg('any', dest, gateway, mask, iface)
            # 添加系统默认生成的路由
            if operate == 'add' and isDefaultRoute == True:
                flag = 'del'
                operate_cfg_file = 'del_cfg'
            # 添加普通的路由
            elif operate == 'add' and isDefaultRoute == False:
                flag = 'any'
                operate_cfg_file = 'add_cfg'
                # 验证路由配置是否正确
                resp = self.verify_route_cfg(dest, gateway, mask, iface)
                if resp.get('code') != 0:
                    return resp
            # 删除系统默认生成的路由
            elif operate == 'delete' and isNormalRoute == False:
                flag = 'del'
                operate_cfg_file = 'add_cfg'
            # 删除普通的路由
            elif operate == 'delete' and isNormalRoute == True:
                flag = 'any'
                operate_cfg_file = 'del_cfg'
            # 创建路由配置信息
            if gateway == '0.0.0.0':
                routeInfo = "{} net {} netmask {} dev {}".format(flag, dest, mask, iface)
            else:
                routeInfo = "{} net {} netmask {} gw {} dev {}".format(flag, dest, mask, gateway, iface)
            # 编辑路由配置文件
            resp = self.edit_route_cfg_file(routeInfo, operate_cfg_file)
            if resp.get('code') != 0:
                return resp
            # 重启网络服务，更新路由表
            restartNetworkCmd = "systemctl restart network"
            (restartNetworkStatus, restartNetworkOutput) = run_cmd(restartNetworkCmd)
            if restartNetworkStatus != 0:
                logger.error("Failed to restart network!!!")
                resp = get_error_result("RestartNetworkError")
                return resp
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("add_or_del_route exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp

    # 验证路由配置是否正确
    def verify_route_cfg(self, dest, gateway, mask, iface):
        try:
            resp = get_error_result("Success")
            # 添加临时路由，用于验证相关路由配置是否正确
            if gateway == '0.0.0.0':
                addTempRouteCmd = "route add -net {} netmask {} dev {}".format(dest, mask, iface)
            else:
                addTempRouteCmd = "route add -net {} netmask {} gw {} dev {}".format(dest, mask, gateway, iface)
            (addTempRouteStatus, addTempRouteOutput) = run_cmd(addTempRouteCmd)
            if addTempRouteStatus != 0:
                if is_include_in_arr(addTempRouteOutput, ['Network is unreachable', '网络不可达']):
                    logger.error("Network is unreachable!!!")
                    resp = get_error_result("NetworkNnreachable")
                    return resp
                elif is_include_in_arr(addTempRouteOutput, ["netmask doesn't match route address"]):
                    logger.error("netmask doesn't match route address!!!")
                    resp = get_error_result("MaskNotMarchAddress")
                    return resp
                elif is_include_in_arr(addTempRouteOutput, ['File exists', '文件已存在']):
                    logger.error("The route already exists!!!")
                    resp = get_error_result("RouteAlreadyExist")
                    return resp
                elif is_include_in_arr(addTempRouteOutput, ['No such device', '没有那个设备']):
                    logger.error("The network card device does not exist!!!")
                    resp = get_error_result("NetCardNotExist")
                    return resp
                else:
                    logger.error("Failed to add temporary route!!!")
                    resp = get_error_result("AddTempRouteError")
                    return resp
            else:
                # 删除刚刚添加的临时路由
                delTempRouteCmd = "route del -net {} netmask {} gw {} dev {}".format(dest, mask, gateway, iface)
                (delTempRouteStatus, delTempRouteOutput) = run_cmd(delTempRouteCmd)
                if delTempRouteStatus != 0:
                    logger.error("Failed to delete temporary route!!!")
                    resp =  get_error_result("DeleteTempRouteError")
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("verify_route_cfg exception: %s" % e)
            logger.error("Route configuration validation failed!!!")
            resp =  get_error_result("RouteCfgVerifyError")
            return resp

    # 编辑路由配置文件
    def edit_route_cfg_file(self, routeInfo, operate_cfg_file):
        resp = get_error_result("Success")
        # 路由配置文件路径
        configDir = "/etc/sysconfig/"
        cfgFileName = "static-routes"
        fullPath = configDir + cfgFileName
        try:
            if operate_cfg_file == 'add_cfg':
                # 判断文件是否存在
                if os.path.exists(fullPath):
                    # 获取文件大小（判断文件内容是否为空）
                    file_size = os.path.getsize(fullPath)
                    with open(fullPath, "a") as cfg:
                        if file_size == 0:
                            cfg.write(routeInfo)
                        else:
                            cfg.write("\n" + routeInfo)
                    # 删除文件中的空白行
                    with open(fullPath, "r+") as file:
                        lines = file.readlines()
                        file.seek(0)
                        for line in lines:
                            if line.strip():  # 判断是否为空白行
                                file.write(line)
                        file.truncate()
                else:
                    with open(fullPath, "w") as cfg:
                        cfg.write(routeInfo)
            elif operate_cfg_file == 'del_cfg':
                # 判断文件是否存在
                if os.path.exists(fullPath):
                    # 读取文件内容并临时存储到lines
                    with open(fullPath, "r") as file:
                        lines = file.readlines()
                    # 将lines中存储端内容后写入文件
                    with open(fullPath, "w") as file:
                        for line in lines:
                            # 如果所在行包含routeInfo则不写入文件
                            if routeInfo not in line:
                                file.write(line)
                else:
                    logger.error("The route configuration file does not exist!!!")
                    resp = get_error_result("RouteCfgFileNotExist")
                    return resp
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("edit_route_cfg_file exception: %s" % e)
            logger.error("Failed to edit the route configuration file!!!")
            resp = get_error_result("EditRouteCfgFileError")
            return resp

    # 检索路由配置信息
    def retrieve_route_cfg(self, flag, dest, gateway, mask, iface):
        # 路由配置文件路径
        configDir = "/etc/sysconfig/"
        cfgFileName = "static-routes"
        fullPath = configDir + cfgFileName
        # 记录routeInfo是否存在
        routeInfoExist = False
        # 创建路由配置信息
        if gateway == '0.0.0.0':
            routeInfo = "{} net {} netmask {} dev {}".format(flag, dest, mask, iface)
        else:
            routeInfo = "{} net {} netmask {} gw {} dev {}".format(flag, dest, mask, gateway, iface)
        # 在配置文件中查找对应的路由
        try:
            # 判断文件是否存在
            if os.path.exists(fullPath):
                # 读取文件内容并临时存储到lines
                with open(fullPath, "r") as file:
                    lines = file.readlines()
                for line in lines:
                    # 如果所在行包含routeInfo则返回True
                    if routeInfo in line:
                        routeInfoExist = True
                        break
            return routeInfoExist
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("retrieve_route_cfg exception: %s" % e)
            logger.error("Failed to retrieve route configuration information!!!")
            return False

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in NetmngCmd.__members__.values()]),
            'hostname': openapi.Schema(type=openapi.TYPE_STRING),
            'operate': openapi.Schema(type=openapi.TYPE_STRING),
            'dest': openapi.Schema(type=openapi.TYPE_STRING),
            'gateway': openapi.Schema(type=openapi.TYPE_STRING),
            'mask': openapi.Schema(type=openapi.TYPE_STRING),
            'iface': openapi.Schema(type=openapi.TYPE_STRING),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))
    def post(self, request, *args, **kwargs):
        ret = get_error_result("Success")
        command = request.data.get("command")
        remote_ip = request.META.get('HTTP_X_FORWARDED_FOR') if request.META.get(
            'HTTP_X_FORWARDED_FOR') else request.META.get("REMOTE_ADDR")
        user_info = {
            "id": 1,
            "user_name": 'admin',
            "user_ip": remote_ip
        }
        try:
            logger.info("user command: %s , ip %s" % (command, remote_ip))
            msg = "在ip: %s 执行 %s" % (remote_ip, command)
            # 由于高频次调用写入操作日志，导致数据库被锁了
            if command not in ["getHostname", "getAllNicsInfo", "getBonds", "getRouteInfo"]:
                insert_operation_log(msg, ret["msg"], user_info)            
            if command == "getHostname":
                cmd = 'hostnamectl|awk \'$2 == "hostname:" {print $3}\''
                (status, output) = run_cmd(cmd)
                ret = {"hostname": output}
                if status != 0:
                    logger.error("Failed to get the hostname!!!")
                    ret = get_error_result("GetHostnameError")
            elif command == "setHostname":
                hostname = request.data.get("hostname", "")
                # 如果已经主机绑定了，就禁止修改“主机名”
                if ClusterNode.objects.count() > 0:
                    ret = get_error_result("AlreadyBindHost")
                    return JSONResponse(ret)
                cmd = "hostnamectl set-hostname %s" % hostname
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'Too few arguments' in output:
                        logger.error("Hostname cannot be empty!!!")
                        ret = get_error_result("HostnameCannotBeEmpty")
                    else:
                        logger.error("Failed to set the hostname!!!")
                        ret = get_error_result("SetHostnameError")
            elif command == "getAllNicsInfo":
                ret = self.get_network_interfaces()
            elif command == "getBonds":
                bondmng = BondManager()
                ret = bondmng.get_bonds()
            elif command == "setNicInfo":
                interface_name = request.data.get("interface_name", "")
                new_info = request.data.get("interface_info", "")
                # 如果网卡已经用于双机绑定的，也不能修改，否则绑定就失效了
                clusterNode = ClusterNode.objects.first()
                if clusterNode:
                    nodeNic = clusterNode.local_nic if clusterNode.local_nic else find_interface_for_ip(clusterNode.local_ip)
                    if interface_name == nodeNic:
                        ret = get_error_result("NicAlreadyUsedInDoubleControl")
                        return JSONResponse(ret)

                # 如果网卡已经用于心跳线路、复制逻辑卷、VIP，不可以修改网卡IP配置
                heartbeatNics = []
                vipNics = []
                if os.path.exists(HEARTBEAT_CONFIG_FILE_PATH):
                    configDict = read_config_file_to_dict()
                    if configDict and 'vrrp_instance' in configDict.keys() and len(configDict['vrrp_instance']):
                        for vrrpInstName in configDict['vrrp_instance'].keys():
                            vrrpInst = configDict['vrrp_instance'][vrrpInstName]
                            heartbeatNics.append(vrrpInst['interface'])
                            vrrpInstVips = [element.split()[-1].strip() for element in vrrpInst['virtual_ipaddress']]
                            vipNics.extend(vrrpInstVips)
                copyLvNics = []
                if os.path.exists(COPY_LV_CONFIG_PATH):
                    resFiles = glob.glob(os.path.join(COPY_LV_CONFIG_PATH, '*.res'))
                    ipAddresses = []
                    for resFile in resFiles:
                        with open(resFile, 'r') as f:
                            for line in f:
                                if 'address' in line:
                                    ipAddress = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line).group()
                                    ipAddresses.append(ipAddress)
                    for ipAddress in ipAddresses:
                        cmd = f"ip addr | grep {ipAddress} | awk '{{print $NF}}'"
                        nicName = run_cmd(cmd)[1].strip()
                        if nicName:
                            copyLvNics.append(nicName)
                # 判断网卡名，给出对应错误返回
                if interface_name in heartbeatNics:
                    ret = get_error_result("NicAlreadyUsedInHeartbeat")
                    return JSONResponse(ret)
                if interface_name in vipNics:
                    ret = get_error_result("NicAlreadyUsedInVip")
                    return JSONResponse(ret)
                if interface_name in copyLvNics:
                    ret = get_error_result("NicAlreadyUsedInCopyLv")
                    return JSONResponse(ret)
                updateNicStatus = self.update_network_interface(interface_name, new_info)
                if updateNicStatus != True:
                    logger.error("Failed to modify network information!!!")
                    ret = get_error_result("ModifyNetworkInfoError")
                    return JSONResponse(ret)
                (status, output) = run_cmd("systemctl restart network")
                if status != 0:
                    logger.error("Failed to restart network!!!")
                    ret = get_error_result("RestartNetworkError")
                    return JSONResponse(ret)
            elif command == "newBond":
                bondmng = BondManager()
                bond_info = request.data.get("bond_info")
                ip_list = request.data.get("ip_list")
                gate_info = request.data.get("gate_info")
                ret = bondmng.config_bond(bond_info, ip_list, gate_info, [], new_flag=True)
            elif command == "editBond":
                bondmng = BondManager()
                bond_info = request.data.get("bond_info")
                ip_list = request.data.get("ip_list")
                gate_info = request.data.get("gate_info")
                remove_slaves = request.data.get("remove_slaves", [])
                ret = bondmng.config_bond(bond_info, ip_list, gate_info, remove_slaves, new_flag=False)
            elif command == "unBond":
                bondmng = BondManager()
                bond_name = request.data.get("bond_name")
                slaves = request.data.get("slaves")
                ret = bondmng.unbond(bond_name, slaves)
            elif command == "getRouteInfo":
                ret = self.get_route_info()
            elif command == "addORdelRoute":
                ret = self.add_or_del_route(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


def check_drbd(drbdPath):
    '''
    1、检查盘是否存在 
    2、检查如果是drbd盘，则检查是否为Primary角色
    '''
    drbdConfPath = '/usr/local/etc/drbd.d/'
    res_files = [filename for filename in os.listdir(drbdConfPath) if filename.endswith('.res')]
    matching_file = ""

    for filename in res_files:
        file_path = os.path.join(drbdConfPath, filename)
        with open(file_path, 'r') as file:
            file_content = file.read()
            deviceInfo = 'device ' + drbdPath
            if deviceInfo in file_content:
                matching_file = filename
    # drbd盘没有匹配到res配置文件，也即是不普通盘，直接返回True
    if not matching_file:
        return True
    # 匹配到res配置文件，再判断role
    resName = os.path.splitext(filename)[0]
    (status, output) = run_cmd(f"drbdadm role {resName}")
    if status == 0 and 'Primary' in output:
        return True
    else:
        return False

# 特殊处理tgtd服务：检查target的lun是否有效，如果无效则把配置重命名, .conf->.invalid, 如果有效，则 .invalid -> .conf
def handle_tgtd_conf():
    try:
        # 获取所有逻辑卷信息
        for filename in os.listdir(TGTD_CONFIG_FILE_PATH):
            if not filename.endswith(('.conf', '.invalid')):
                continue
            file_path = os.path.join(TGTD_CONFIG_FILE_PATH, filename)
            with open(file_path, 'r') as f:  
                content = f.read()  
            # 使用正则表达式提取所有的backing-store值  
            backing_stores = [line.split(' ')[1].strip() for line in content.split('\n') if 'backing-store' in line]  
            # 检查每个设备是否存在，得到新文件名后缀
            basename, old_suffix = os.path.splitext(file_path)
            new_suffix = ".conf"
            for device in backing_stores:  
                if not os.path.exists(device):
                    logger.warn(f'{device} not exists, set tgtd conf to .invalid')  
                    new_suffix = ".invalid"
                if not check_drbd(device):
                    logger.warn(f'{device} drbd role not Primary, set tgtd conf to .invalid')  
                    new_suffix = ".invalid"
            new_file_path = f"{basename}{new_suffix}"
            # target 实际有效性发生变化，则变更文件名后缀
            if new_suffix != old_suffix:
                os.rename(file_path, new_file_path)
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))

# 特殊处理nfs服务：检查共享目录是否有效，如果无效则把配置最前面添加#号注释，如果有效则去掉最前面#号
def handle_nfs_conf():
    try:
        lines = []  # 有效的配置行
        with open(NFS_CONFIG_FILE, 'r') as file:
            for line in file:
                line = line.strip()  # 去除行首尾的空白字符
                # 获取每行的目录信息和权限信息
                authInfo = " ".join(line.split()[1:])
                nfsPath = line.split()[0]
                if line.startswith("#/"):
                    nfsPath = line[1:].split()[0]
                # 根据目录是否存在，组新的配置行
                newLine = nfsPath + " " + authInfo
                if not os.path.exists(nfsPath):
                    newLine = "#" + nfsPath + " " + authInfo
                # 新行信息追加到所有行的数组中
                lines.append(newLine)
        # 将有效行写回文件
        with open(NFS_CONFIG_FILE, 'w') as file:
            for line in lines:
                file.write(line + "\n")
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))        


class SrvmngView(APIView):

    """service manage"""

    # 开启服务
    def start(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            service_name = request.data.get('service')
            service_list = []
            if type(service_name) is str:
                service_list.append(service_name)
            elif type(service_name) is list:
                service_list = service_name
            else:
                logger.error('request data type error')
                return get_error_result("MessageError")
            for service in service_list: 
                logger.debug('start {}'.format(service))
                if service == "tgtd":
                    handle_tgtd_conf()
                elif service == "nfs":
                    handle_nfs_conf()
                if service:
                    run_cmd('systemctl start {}'.format(service))
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp

    # 关闭服务
    def stop(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            service_name = request.data.get('service')
            service_list = []
            if type(service_name) is str:
                service_list.append(service_name)
            elif type(service_name) is list:
                service_list = service_name
            else:
                logger.error('request data type error')
                return get_error_result("MessageError")
            for service in service_list: 
                logger.debug('stop {}'.format(service))
                if service:
                    run_cmd('systemctl stop {}'.format(service))
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp

    # 重启服务
    def restart(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            service_name = request.data.get('service')
            service_list = []
            if isinstance(service_name, str):
                service_list.append(service_name)
            elif isinstance(service_name, list):
                service_list = service_name
            else:
                logger.error('request data type error')
                return get_error_result("MessageError")
            for service in service_list: 
                logger.info('restart {}'.format(service))
                if service == "tgtd":
                    handle_tgtd_conf()
                elif service == "nfs":
                    handle_nfs_conf()                    
                run_cmd('systemctl restart {}'.format(service))
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp

    # 服务状态
    def status(self, request, *args, **kwargs):
        try:
            service_name = request.data.get('service')
            return self.get_service_status(service_name)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp

    # 设置服务开机启动
    def enable(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            service_name = request.data.get('service')
            service_list = []
            if type(service_name) is str:
                service_list.append(service_name)
            elif type(service_name) is list:
                service_list = service_name
            else:
                logger.error('request data type error')
                return get_error_result("MessageError")
            for service in service_list: 
                logger.debug('enable {}'.format(service))
                if service:
                    run_cmd('systemctl enable {}'.format(service))
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp

    # 禁用开机启动
    def disable(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            service_name = request.data.get('service')
            service_list = []
            if type(service_name) is str:
                service_list.append(service_name)
            elif type(service_name) is list:
                service_list = service_name
            else:
                logger.error('request data type error')
                return get_error_result("MessageError")
            for service in service_list: 
                logger.debug('disable {}'.format(service))
                if service:
                    run_cmd('systemctl disable {}'.format(service))
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp    

    # 动态监控系统服务（暂未实现）
    def get_services(self):
        try:
            services = []
            # work_dir = os.getcwd()
            work_dir = os.path.join('./', 'config')
            conf = configparser.ConfigParser()
            conf.read('{}/monitor_services.ini'.format(work_dir))
            for key in conf['SERVICES']:
                if conf['SERVICES'][key] == "true":
                    services.append(key)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))

    # 获取服务状态
    def get_service_status(self, service_name):
        try:
            result = subprocess.run(['systemctl', 'status', service_name], capture_output=True, text=True)
            output = result.stdout
            resp = {"name": service_name, "status": "Unknown", "enabled": "Unknown"}
    
            # 解析开机加载状态
            match = re.search(r'Loaded: .+\; (.+)\;', output)
            if match:
                bootload_status = match.group(1).strip()
                resp["enabled"] = True if bootload_status == "enabled" else False
    
            # 解析运行状态
            match = re.search(r'Active: .+\((.+)\)', output)
            if match:
                running_status = match.group(1).strip()
                resp["status"] = running_status
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))

    def get(self, request, *args, **kwargs):
        # 从配置文件中获取需要监控的所有服务列表信息
        try:
            resp = []
            for service in MONITOR_SERVICES:
                resp.append(self.get_service_status(service))

            return JSONResponse(resp)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result(error="OtherError")
            return resp  

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING),
            'service': openapi.Schema(type=openapi.TYPE_STRING),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command', 'service'],
    ))
    def post(self, request, *args, **kwargs):
        ret = get_error_result("Success")
        command = request.data.get("command")
        remote_ip = request.META.get('HTTP_X_FORWARDED_FOR') if request.META.get(
            'HTTP_X_FORWARDED_FOR') else request.META.get("REMOTE_ADDR")
        user_info = {
            "id": 1,
            "user_name": 'admin',
            "user_ip": remote_ip
        }
        try:

            logger.info("user command: %s , ip %s" % (command, remote_ip))
            msg = "在ip: %s 执行 %s" % (remote_ip, command)
            # 由于高频次调用写入操作日志，导致数据库被锁了
            if command not in ["status"]:
                insert_operation_log(msg, ret["msg"], user_info)
            if command == "restart":
                ret = self.restart(request, args, kwargs)
            elif command == "start":
                ret = self.start(request, args, kwargs)
            elif command == "stop":
                ret = self.stop(request, args, kwargs)
            elif command == "enable":
                ret = self.enable(request, args, kwargs)
            elif command == "disable":
                ret = self.disable(request, args, kwargs)
            elif command == "status":
                ret = self.status(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


class PropertyView(APIView):
    """Property manage"""
    def get(self, request, *args, **kwargs):
        try:
            ret = get_error_result("Success")
            cmd = 'iostat -x -k  -d 1 1'
            diskdata = run_cmd(cmd)[1].split('\n')

            lv_arr = []
            net_arr = []

            for items in diskdata:
                if "dm-" in items:
                    item = items.split()
                    name = item[0]
                    r_s = item[1]
                    rKB_s = item[2]
                    w_s = item[7]
                    wKB_s = item[8]
                    lvdata = {'name':name,'r/s':r_s,'rKB/s':rKB_s,'w/s':w_s,'wKB/s':wKB_s}
                    lv_arr.append(lvdata)
                    logger.debug(items)


            ret['data'] = lv_arr
            return JSONResponse(ret)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


class VermngCmd(Enum):
    GetCurrentVersion = "getCurrentVersion"
    Upgrade = "upgrade"

UNZIP_FILENAME='/tmp/unzip_file_name'
import json
class VermngView(APIView):
    """Version manage"""
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in VermngCmd.__members__.values()]),
            'date_time': openapi.Schema(type=openapi.TYPE_STRING),
            'timezone': openapi.Schema(type=openapi.TYPE_STRING),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))
    def post(self, request, *args, **kwargs):
        ret = get_error_result("Success")
        command = request.data.get("command")
        remote_ip = request.META.get('HTTP_X_FORWARDED_FOR') if request.META.get(
            'HTTP_X_FORWARDED_FOR') else request.META.get("REMOTE_ADDR")
        user_info = {
            "id": 1,
            "user_name": 'admin',
            "user_ip": remote_ip
        }
        try:

            logger.info("user command: %s , ip %s" % (command, remote_ip))
            msg = "在ip: %s 执行 %s" % (remote_ip, command)
            insert_operation_log(msg, ret["msg"], user_info)
            if command == "getCurrentVersion":
                ret = self.get_current_version()
            elif command == "upgrade":
                logger.debug(f'访问方式:{request.method},  文件：{request.FILES["file"]}')
                self.software_upgrade(request, args, kwargs)

                ret = get_error_result("Success")
                #ret = self.software_upgrade(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    # 获取当前软件版本
    def get_current_version(self):
        resp = get_error_result("Success")
        try:
            # 构建当前版本信息字典
            curr_version_info = {}
            # 将版本信息存放到字典中
            curr_version_info['version'] = VERSION if VERSION else "Unknown"
            resp = get_error_result("Success", curr_version_info)
            return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("get_current_version exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp

    # 软件升级
    def software_upgrade(self, request, args, kwargs):
        resp = get_error_result("Success")
        try:
            # 接收从前端上传的文件
            resp = self.receive_file(request)
            if resp.get('code') != 0:
                return resp
            file_name = resp.get('data')
            # 备份当前软件
            resp = self.backup_dir()
            if resp.get('code') != 0:
                return resp
            # 解压上传的文件
            resp = self.unzip_file(file_name)
            if resp.get('code') != 0:
                return resp
            unzip_dir_name = resp.get('data')
            file = open(UNZIP_FILENAME, "w")
            file.write(unzip_dir_name)
            file.close()

            return resp
            # thePid = os.fork()
            # if thePid > 0:
            #     # 父进程退出
            #     os._exit(0)
            # os.setsid()
            # thePid = os.fork()
            # if thePid > 0:
            #     # 第一个子进程退出，留下第二个子进程作为守护进程
            #     resp = get_error_result("Success")
            #     return resp
            
            # time.sleep(5)#给父进程充分的时间返回应答给前端
            # pid = os.getppid()
            # os.system(f'kill -9 {pid}')

            # os.system(f'chmod 777 {shell_script_path}')
            # os.execl(shell_script_path, shell_script_path, unzip_dir_name)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("software_upgrade exception: %s" % e)
            resp = get_error_result("OtherError")
            return resp

    def receive_file(self, request):
        resp = get_error_result("Success")
        try:
            if request.method == 'POST' and request.FILES['file']:
                uploaded_file = request.FILES['file']
                file_path = ROOT_DIR + uploaded_file.name
                #logger.debug("uploaded_file.name ===> %s", uploaded_file.name)
                # 使用正则表达式判断上传的文件名是否符合规范，如"manage_v1.0.0.tar.gz"
                regex = r'^manage_v\d+\.\d+\.\d+\.tar\.gz$'
                is_file_name_valid = re.match(regex, uploaded_file.name) is not None
                if is_file_name_valid:
                    # 保存文件
                    with open(file_path, 'wb') as destination:
                        for chunk in uploaded_file.chunks():
                            destination.write(chunk)
                else:
                    logger.error("The uploaded file does not meet the specifications!!!")
                    resp =  get_error_result("UploadedFileNotSpec")
                    return resp
                resp = get_error_result("Success", uploaded_file.name)
                return resp
            else:
                logger.error("Failed to upload the file!!!")
                resp =  get_error_result("UploadFileError")
                return resp
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("receive_file exception: %s" % e)
            logger.error("Failed to receive the file!!!")
            resp =  get_error_result("ReceiveFileError")
            return resp

    # 备份目录
    def backup_dir(self):
        resp = get_error_result("Success")
        # 获取当前时间
        current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        # 构建备份目录名称
        backup_dir_name = f"{PRIMARY_DIR_NAME}_bak_{current_time}"
        # 关闭sqlite3打开的所有句柄
        connection.close()
        # 创建备份
        backupCmd = "cp -rp --no-preserve=timestamps {}{} {}{}".format(ROOT_DIR, PRIMARY_DIR_NAME, ROOT_DIR, backup_dir_name)
        (backupStatus, backupOutput) = run_cmd(backupCmd)
        if backupStatus != 0:
            logger.error(f"Failed to backup the current version ===> {backupOutput}!!!")
            resp = get_error_result("BackupSwError")
            return resp
        return resp

    # 解压文件
    def unzip_file(self, file_name):
        resp = get_error_result("Success")
        # 解压缩
        unzipCmd = "tar -xf {}{} -C {}".format(ROOT_DIR, file_name, ROOT_DIR)
        (unzipStatus, unzipOutput) = run_cmd(unzipCmd)
        if unzipStatus != 0:
            logger.error(f"Failed to unzip the file ===> {unzipOutput}!!!")
            resp = get_error_result("UnzipFileError")
            return resp
        # 获取解压后的目录名称
        getDirCmd = "tar -tf {}{} | head -n 1 | sed 's/\///g'".format(ROOT_DIR, file_name)
        (getDirStatus, getDirOutput) = run_cmd(getDirCmd)
        unzip_dir_name = getDirOutput
        resp = get_error_result("Success", unzip_dir_name)
        return resp


 # 替换数据库文件
    def replace_data_file(self, unzip_dir_name):
        resp = get_error_result("Success")
        # 关闭sqlite3打开的所有句柄
        connection.close()
        # 删除数据库文件
        delDateCmd = "rm -rf {}{}/{}".format(ROOT_DIR, unzip_dir_name, DATABASE_FILE_NAME)
        (delDateStatus, delDateOutput) = run_cmd(delDateCmd)
        # 拷贝数据库文件
        copyDateCmd = "cp -rp {}{}/{} {}{}".format(ROOT_DIR, PRIMARY_DIR_NAME, DATABASE_FILE_NAME, ROOT_DIR, unzip_dir_name)
        (copyDateStatus, copyDateOutput) = run_cmd(copyDateCmd)
        if copyDateStatus != 0:
            logger.error(f"Failed to copy database files ===> {copyDateOutput}!!!")
            resp = get_error_result("CopyDateFileError")
            return resp
        return resp

    # 替换目录
    def replace_dir(self, unzip_dir_name):
        resp = get_error_result("Success")
        # 关闭sqlite3打开的所有句柄
        connection.close()
        # 删除旧目录
        delOldDirCmd = "rm -rf {}{}".format(ROOT_DIR, PRIMARY_DIR_NAME)
        (delOldDirStatus, delOldDirOutput) = run_cmd(delOldDirCmd)
        if delOldDirStatus != 0:
            logger.error(f"Failed to delete the old directory ===> {delOldDirOutput}.!!!")
            resp = get_error_result("DeleteOldDirError")
            return resp
        # 重命名新目录
        renameDirCmd = "mv {}{} {}{}".format(ROOT_DIR, unzip_dir_name, ROOT_DIR, PRIMARY_DIR_NAME)
        (renameDirStatus, renameDirOutput) = run_cmd(renameDirCmd)
        if renameDirStatus != 0:
            logger.error(f"Failed to rename the new directory ===> {renameDirOutput}!!!")
            resp = get_error_result("RenameNewDirError")
            return resp
        return resp

    # 重启storemng服务
    def restart_storemng(self):
        resp = get_error_result("Success")
        resStoremngCmd = "systemctl restart storemng"
        (resStoremngStatus, resStoremngOutput) = run_cmd(resStoremngCmd)
        if resStoremngStatus != 0:
            logger.error(f"Failed to restart storemng service ===> {resStoremngOutput}!!!")
            resp = get_error_result("RestartStoremngError")
            return resp
        return resp

    # 检查storemng服务状态
    def check_storemng(self):
        resp = get_error_result("Success")
        checkServiceCmd = "systemctl status storemng.service | grep -i error"
        (checkServiceStatus, checkServiceOutput) = run_cmd(checkServiceCmd)
        if checkServiceOutput:
            logger.error(f"Storemng service exception ===> {checkServiceOutput}!!!")
            resp = get_error_result("StoremngException")
            return resp
        return resp