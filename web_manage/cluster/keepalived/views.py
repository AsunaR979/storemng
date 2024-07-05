import glob
import random
import shutil
import subprocess
import traceback
import logging
import re
import os
from scapy.all import sniff, IP
from django.db import connection
import netaddr
from enum import Enum
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from web_manage.common.constants import COPY_LV_CONFIG_PATH, DOUBLE_CONTROL_CONFIG_PATH, DOUBLE_CONTROL_LOG_PATH, HEARTBEAT_CONFIG_FILE_PATH, HEARTBEAT_IP
from web_manage.common.srvmng import get_service_status, reload_service, restart_service, start_service
from web_manage.common.utils import JSONResponse, generate_password, get_error_result, get_device_mountpoint, get_ipv4_addresses
from web_manage.common.cmdutils import run_cmd
from web_manage.common.log import insert_operation_log
from web_manage.admin.models import AdminUser
from web_manage.cluster.models import *
from web_manage.common.http import peer_post
from web_manage.common.utils import check_ip_on_interface

logger = logging.getLogger(__name__)


class HostconfCmd(Enum):
    BindHost = "bindHost"
    UnbindHost = "unbindHost"
    GetBindInfo = "getBindInfo"


class HostconfView(APIView):
    """主机绑定"""
    """主机解绑"""
    """获取主机绑定信息"""
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in HostconfCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'localIp': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteIp': openapi.Schema(type=openapi.TYPE_STRING),
            # 这个值只有后端请求会给
            'remoteHostname': openapi.Schema(type=openapi.TYPE_STRING),
            'password': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command == "bindHost":
                ret = self.bind_host(request, args, kwargs)
            elif command == "unbindHost":
                ret = self.unbind_host(request, args, kwargs)
            elif command == "getBindInfo":
                ret = self.get_bind_info(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def local_bind_host(self, request, hostname):
        '''
        本地绑定：对端ip、对端hostname，成功绑定则返回本地的hostname给对端
        默认情况下：前端无需知道双机的hostname
        '''
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            remoteIp = request.data.get('remoteIp')
            remoteHostname = request.data.get('remoteHostname')
            localIp = request.data.get('localIp')
            localNic = request.data.get('localNic')

            # 获取当前节点的hostname,返回给对端用于绑定
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            # 判断主机名是否一致
            if localHostname == remoteHostname:
                logger.error("hostname can not the same !!!")
                resp = get_error_result("TwoHostHadTheSameHostname")
                return resp
            # 判断是否已经做过绑定
            if ClusterNode.objects.count():
                logger.error("already bind a peer host!!!")
                resp = get_error_result("ExsitsClusterNodeData")
                return resp
            
            if requestEnd == "frontend":
                remoteHostname = hostname
            else:
                # 不验证当前节点请求的密码，只需要验证对端密码
                pwd = request.data.get('password')
                if remoteIp and remoteHostname and pwd:
                    # 判断本机的所有网卡是否都是静态配置好了ip信息，已经是否配置hostname，这些绑定后无法修改
                    # 先验证管理员密码
                    obj = AdminUser.objects.filter(
                        deleted=False, username="admin").first()
                    if not obj or not obj.validate_password(pwd):
                        logger.error("admin password error:!!!")
                        return get_error_result("LoginFailError")
                else:
                    resp = get_error_result("MessageError")
                    return resp
            
            # 记录对端机器ip、hostname信息
            values = {
                "local_ip": localIp,
                "local_nic": localNic,                
                "ip": remoteIp,
                "host_name": remoteHostname,
                "status": 0
            }
            # 数据插入数据库保存
            ClusterNode.objects.create(**values)

            resp.update({"data": {"remoteHostname": localHostname}})

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def remote_bind_host(self, request):
        try:
            resp = get_error_result("Success")
            localIp = request.data.get('localIp')
            remoteIp = request.data.get('remoteIp')
            pwd = request.data.get('password')
            # 获取当前节点的hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp

            data = {
                "command": "bindHost",
                "requestEnd": "backend",
                "remoteIp": localIp,
                "remoteHostname": localHostname,
                "password": pwd
            }
            # 第一次绑定主机前，数据库没有记录对端ip地址，需要作为参数传入才行
            return peer_post("/cluster/doubleCtlSetting/hostconf", data, remoteIp)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def bind_host(self, request, *args, **kwargs):
        """把对端主机信息记录到cluster_node数据库配置中"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            if requestEnd == "frontend":
                # 先远程绑定主机
                resp = self.remote_bind_host(request)
                if resp.get('code') != 0:
                    logger.error("remote bind host failed!!!")
                    return resp
                # 解析远程返回的对端机器hostanme,用于本地绑定
                remoteHostname = resp.get("data").get("remoteHostname")
                # 本地绑定主机
                resp = self.local_bind_host(request, remoteHostname)
                if resp.get('code') != 0:
                    logger.error("local bind host failed!!!")
                    # 回滚对端
                    self.remote_unbind_host(request)
                    return resp                
            else:
                # 后端请求会在request里自带remoteHostname
                resp = self.local_bind_host(request, None)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_local_unbind_host(self, request):
        try:
            # 数据删除数据库
            clusterNode = self.cacheData['clusterNode']
            if clusterNode:
                clusterNode.save()
        except Exception as err:
            logger.error(f"rollback_local_bind_host exception {err}")
            logger.error(''.join(traceback.format_exc()))	

    def local_unbind_host(self, request):
        try:
            resp = get_error_result("Success")
            remoteIp = request.data.get('remoteIp')
            # 备份数据库记录，用于回滚
            self.cacheData['clusterNode'] = ClusterNode.objects.first()
            
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def remote_unbind_host(self, request):
        try:
            resp = get_error_result("Success")
            localIp = request.data.get('localIp')
            data = {
                "command": "unbindHost",
                "requestEnd": "backend",
                "remoteIp": localIp
            }
            return peer_post("/cluster/doubleCtlSetting/hostconf", data)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def unbind_host(self, request, *args, **kwargs):
        """把对端主机信息从cluster_node数据表删除"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            remoteIp = request.data.get('remoteIp')
            if requestEnd == "frontend":
                # 判断是否还有心跳线路、复制逻辑卷、
                if os.path.exists(HEARTBEAT_CONFIG_FILE_PATH):
                    configDict = read_config_file_to_dict()
                    if configDict and 'vrrp_instance' in configDict.keys() and len(configDict['vrrp_instance']):
                        resp = get_error_result("ExistsHearbeatLineResource")
                        return resp
                if os.path.exists(COPY_LV_CONFIG_PATH):                    
                    resFiles = glob.glob(os.path.join(COPY_LV_CONFIG_PATH, '*.res'))
                    if len(resFiles):
                        resp = get_error_result("ExistsCopyLvResource")
                        return resp
                # 本地
                resp = self.local_unbind_host(request)
                if resp.get('code') != 0:
                    logger.error("local unbind host failed!!!")
                    return resp
                # 远程
                resp = self.remote_unbind_host(request)
                if resp.get('code') != 0:
                    logger.error("remote unbind host failed!!!")
                    # 回滚本地
                    self.rollback_local_unbind_host(request)
                    return resp
                # 数据库删除记录
                ClusterNode.objects.first().delete()
            else:
                resp = self.local_unbind_host(request)
                if resp.get('code') != 0:
                    logger.error("local unbind host failed!!!")
                    return resp
                # 数据库删除记录
                ClusterNode.objects.first().delete()
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_bind_info(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            # 获取所有的节点信息，过滤掉当前主机，双击环境就只剩下对端
            clusterNode = ClusterNode.objects.values("ip", "host_name", "status").first()
            if clusterNode:
                resp = get_error_result("Success", data=clusterNode)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp


class PeerconfCmd(Enum):
    GetAllNicInfo = "getAllNicInfo"
    GetAllLvInfo = "getAllLvInfo"
    ServiceMng = "serviceMng"


class PeerconfView(APIView):
    """获取对端主机相关信息"""
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in PeerconfCmd.__members__.values()]),
            'srvcmd': openapi.Schema(type=openapi.TYPE_STRING),
            'srvname': openapi.Schema(type=openapi.TYPE_STRING),
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
            # 处理单机运行情况 
            if ClusterNode.objects.count() == 0:
                logger.warning("单机运行中……")
                ret = get_error_result("Success")
                return JSONResponse(ret)
            else:
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status", "double_control_status").first()
                if peerInfo["double_control_status"] == "standAlone":
                    ret = get_error_result("Success")
                    return JSONResponse(ret)

            if command == "getAllNicInfo":
                ret = self.get_all_nic_info(request)
            elif command == "getAllLvInfo":
                ret = self.get_all_lv_info(request)
            elif command == "serviceMng":
                ret = self.service_manage(request)                
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def get_all_lv_info(self, request):
        try:
            resp = get_error_result("Success")
            data = {
                "command": "getAllLvDetail",
            }
            return peer_post("/hardware/lvm/lv/operate", data)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_all_nic_info(self, request):
        try:
            resp = get_error_result("Success")
            data = {
                "command": "getAllNicsInfo",
            }
            return peer_post("/sysmng/netmng/operate/", data)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def service_manage(self, request):
        try:
            resp = get_error_result("Success")
            data = {
                "command": request.data.get("srvcmd"),
                "service": request.data.get("srvname")
            }
            return peer_post("/sysmng/srvmng/operate/", data)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp        


class SrvMngCmd(Enum):
    GetAllServiceInfo = "getAllServiceInfo"


class SrvMngView(APIView):
    """获取双控服务相关信息"""
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in SrvMngCmd.__members__.values()]),
            'localIp': openapi.Schema(type=openapi.TYPE_STRING),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command', 'localIp'],
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
            if command == "getAllServiceInfo":
                ret = self.get_all_service_info(request)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def get_all_service_info(self, request):
        try:
            resp = get_error_result("Success")
            localIp = request.data.get("localIp")
            # 1、数据库获取绑定对端机器的ip、hostname、然后根据请求对端获取keepalived服务的状态即可
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp

            result = subprocess.run(['systemctl', 'status', "keepalived"], capture_output=True, text=True)
            output = result.stdout
            (enabled, status) = ("Unknown", "Unknown")
    
            # 解析开机加载状态
            match = re.search(r'Loaded: .+\; (.+)\;', output)
            if match:
                bootload_status = match.group(1).strip()
                enabled = True if bootload_status == "enabled" else False
    
            # 解析运行状态
            match = re.search(r'Active: .+\((.+)\)', output)
            if match:
                running_status = match.group(1).strip()
                status= running_status

            localInfo = {
                "nodeIp": localIp,
                "hostname": localHostname,
                "enabled": enabled,
                "status": status
            }
            # 2、获取对端机器的ip、hostname和keepalived状态
            remoteIp = ""
            remoteHost = ""
            if not  ClusterNode.objects.count():
                respData = [localInfo]
                return get_error_result("Success", respData)
            peerInfo = ClusterNode.objects.values("ip", "host_name", "status", "double_control_status").first()
            # 兼容脱机情况直接返回本地数据
            if peerInfo["double_control_status"] == "standAlone":
                respData = [localInfo]
                return get_error_result("Success", respData)
            # 双机通信正常，则获取对端信息
            if peerInfo and peerInfo["status"] != -1:
                remoteIp = peerInfo["ip"]
                remoteHost = peerInfo["host_name"]
                # 发起http请求获取对端机器的keepalived的状态
                reqData = {
                    "command": "status",
                    "requestEnd": "backend",
                    "service": "keepalived"
                }
                remoteKeepalivedStatus = "Unknown"
                remoteEnabled = "Unknown"
                remoteResp = peer_post("/sysmng/srvmng/operate/", reqData)
                if remoteResp.get("code") == 0:
                    remoteKeepalivedStatus = remoteResp.get('data').get("status")
                    remoteEnabled = remoteResp.get('data').get("enabled")
                remoteInfo = {
                    "nodeIp": remoteIp,
                    "hostname": remoteHost,
                    "enabled": remoteEnabled,
                    "status": remoteKeepalivedStatus
                }
                respData = [localInfo, remoteInfo]
            else:
                respData = [localInfo]
            return get_error_result("Success", respData)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp    



'''
{
	'global_defs': {
		'router_id': 'kpmaster'
	},
	'vrrp_script': {
		'vrrp_script chk_keepalived1': {
			'script': '/bin/bash /data/scripts/keepalived_check1.sh',
			'interval': '1',
			'weight': '-10'
		},
		'vrrp_script chk_keepalived2': {
			'script': '/bin/bash /data/scripts/keepalived_check2.sh',
			'interval': '1',
			'weight': '-10'
		}
	},
	'vrrp_instance': {
		'vrrp_instance vi1': {
			'state': 'MASTER',
			'interface': 'eth0',
			'virtual_router_id': '51',
			'priority': '150',
			'advert_int': '1',
			'authentication': {
				'auth_type': 'PASS',
				'auth_pass': 'k@l!ve1'
			},
			'virtual_ipaddress': ['192.168.200.10', '192.168.200.11'],
			'track_script': ['chk_keepalived1']
		},
		'vrrp_instance vi2': {
			'state': 'MASTER',
			'interface': 'eth1',
			'virtual_router_id': '52',
			'priority': '150',
			'advert_int': '1',
			'authentication': {
				'auth_type': 'PASS',
				'auth_pass': 'k@l!ve2'
			},
			'virtual_ipaddress': ['192.168.100.10'],
			'track_script': ['chk_keepalived2']
		}
	}
}

'''


def read_config_file_to_dict():
    try:
        global_defs_dict = None
        vrrp_script_dict = None
        vrrp_instance_dict = None
        cfgFile = HEARTBEAT_CONFIG_FILE_PATH
        if os.path.exists(cfgFile) is False:
            os.open(cfgFile, os.O_CREAT)
            os.chmod(cfgFile, 640)
            os.close(cfgFile)
        with open(cfgFile, 'r') as file:
            content = file.read()

        # 解析global_defs
        global_defs_match = re.search(
            r'global_defs \{\s*\n(.*?)\n\s*\}', content, re.DOTALL)
        if global_defs_match:
            global_defs_str = global_defs_match.group(1)
            global_defs_dict = {}
            for line in global_defs_str.split('\n'):
                if line.strip() != '':
                    key, value = line.strip().split()
                    global_defs_dict[key] = value

        # 解析vrrp_script
        vrrp_script_dict = {}
        vrrp_script_matches = re.findall(
            r'vrrp_script (\w+) \{\s*\n(.*?)\n\s*\}', content, re.DOTALL)
        for name, script_str in vrrp_script_matches:
            name = "vrrp_script " + name
            vrrp_script_dict[name] = {}
            for line in script_str.split('\n'):
                if line.strip() != '':
                    items = line.strip().split()
                    if len(items) > 2:
                        key = items[0]
                        value = (" ").join(items[1:len(items)])
                    else:
                        key, value = line.strip().split()
                    vrrp_script_dict[name][key] = value.strip('"')

        # 解析vrrp_instance
        vrrp_instance_dict = {}
        vrrp_instance_matches = re.findall(
            r'vrrp_instance (\w+) \{\s*\n(.*?)\n\}', content, re.DOTALL)
        for name, instance_str in vrrp_instance_matches:
            name = "vrrp_instance " + name
            vrrp_instance_dict[name] = {}
            subDictContent = ""
            for line in instance_str.split('\n'):
                if line.strip() != '':
                    if '}' in line:
                        subDictContent += (line + "\n")
                        # print(subDictContent)
                        # 解析新的嵌套字典
                        key = subDictContent.strip().split("{")[0].strip()
                        if key in ["virtual_ipaddress", "track_script"]:
                            value = parse_single_array(subDictContent)
                        else:
                            value = parse_single_dict(
                                subDictContent, key)
                        vrrp_instance_dict[name][key.strip()] = value
                        # 原始变量置空
                        subDictContent = ""
                    elif '{' in line or subDictContent != "":
                        # 组新的字典原始文本
                        subDictContent += (line + "\n")
                        continue
                    else:
                        items = line.strip().split()
                        if len(items) > 2:
                            key = items[0]
                            value = (" ").join(items[1:len(items)])
                        else:
                            key, value = line.strip().split()
                        vrrp_instance_dict[name][key] = value
        # 构建字典
        configDict = {}
        if global_defs_dict:
            configDict.update({"global_defs": global_defs_dict})
        if vrrp_script_dict:
            configDict.update({"vrrp_script": vrrp_script_dict})
        if vrrp_instance_dict:
            configDict.update({"vrrp_instance": vrrp_instance_dict})
        return configDict
    except Exception as err:
        logger.error(f"call read_config_file_to_dict error: {err}")
        logger.error(''.join(traceback.format_exc()))


def config_info_to_file(configDict):
    try:
        cfgStr = ""
        if 'global_defs' in configDict.keys():
            cfgStr = generate_config_string(
                configDict['global_defs'], 1, 'global_defs')
        if 'vrrp_script' in configDict.keys():
            cfgStr += generate_config_string(
                configDict['vrrp_script'], 0, "vrrp_script")
        if 'vrrp_instance' in configDict.keys():
            cfgStr += generate_config_string(
                configDict['vrrp_instance'], 0, "vrrp_instance")
        with open(HEARTBEAT_CONFIG_FILE_PATH, 'w') as file:
            file.write(cfgStr)
        return get_error_result("Success")
    except Exception as err:
        logger.error(f"call config_info_to_file error: {err}")
        logger.error(''.join(traceback.format_exc()))
        ret = get_error_result("OtherError")
        return JSONResponse(ret)


def generate_config_string(config, indent_level=0, name=None):
    try:
        indent = "   " * indent_level
        result = ""

        if name in ['global_defs']:
            result += name + " {\n"

        for key, value in config.items():

            if isinstance(value, dict):
                result += indent + key + " {\n"
                result += generate_config_string(value, indent_level + 1)
                result += indent + "}\n"
            elif isinstance(value, list):
                result += indent + key + " {\n"
                for item in value:
                    result += indent + "   " + str(item) + "\n"
                result += indent + "}\n"
            else:
                if " " in value:
                    value = value.strip('"')
                    result += indent + key + " \"" + str(value) + "\"\n"
                else:
                    result += indent + key + " " + str(value) + "\n"

        if name in ['global_defs']:
            result += "}\n"

        return result
    except Exception as err:
        logger.error(f"call generate_config_string error: {err}")
        logger.error(''.join(traceback.format_exc()))


def parse_single_array(arrayContent):
    try:
        defs_array = []
        defs_match = re.search(
            r'\{\s*\n(.*?)\n\s*\}', arrayContent, re.DOTALL)
        if defs_match:
            defs_str = defs_match.group(1)
            for line in defs_str.split('\n'):
                if line.strip() != '':
                    defs_array.append(line.strip())
        return defs_array
    except Exception as err:
        logger.error(f"call parse_single_array error: {err}")
        logger.error(''.join(traceback.format_exc()))


def parse_single_dict(dictContent, dictkeyName):
    try:
        defs_dict = {}
        defs_match = re.search(
            r'\{\s*\n(.*?)\n\s*\}', dictContent, re.DOTALL)
        if defs_match:
            defs_str = defs_match.group(1)
            defs_dict = {}
            for line in defs_str.split('\n'):
                if line.strip() != '':
                    key, value = line.strip().split()
                    defs_dict[key] = value
        return defs_dict
    except Exception as err:
        logger.error(f"call parse_single_dict error: {err}")
        logger.error(''.join(traceback.format_exc()))


class HeartbeatCmd(Enum):
    AddHeartbeat = "addHeartbeat"
    DeleteHeartbeat = "deleteHeartbeat"
    UpdateHeartbeatInfo = "updateHeartbeatInfo"
    StartHeartbeatService = "startHeartbeatService"
    StopHeartbeatService = "stopHeartbeatService"
    GetSingleHeartbeatDetail = "getSingleHeartbeatDetail"
    GetAllHeartbeatInfo = "getAllHeartbeatInfo"
    SetAutoRestore = "setAutoRestore"
    GetDoubleControlOverview = "getDoubleControlOverview"


class HeartbeatView(APIView):
    """心跳管理"""
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in HeartbeatCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'viNum': openapi.Schema(type=openapi.TYPE_STRING),
            'localNic': openapi.Schema(type=openapi.TYPE_STRING),
            'localIp': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteNic': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteIp': openapi.Schema(type=openapi.TYPE_STRING),
            'isEnableAutoRestore': openapi.Schema(type=openapi.TYPE_BOOLEAN),
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
            if command not in ["getSingleHeartbeatDetail", "getAllHeartbeatInfo", "getDoubleControlOverview"]:
                insert_operation_log(msg, ret["msg"], user_info)
            if command == "addHeartbeat":
                ret = self.add_heartbeat(request, args, kwargs)
            elif command == "deleteHeartbeat":
                ret = self.delete_heartbeat(request, args, kwargs)
            elif command == "updateHeartbeatInfo":
                ret = self.update_heartbeat(request, args, kwargs)                
            elif command == "startHeartbeatService":
                ret = self.start_heartbeat_service(request, args, kwargs)
            elif command == "stopHeartbeatService":
                ret = self.stop_heartbeat_service(request, args, kwargs)                
            elif command == "getSingleHeartbeatDetail":
                ret = self.get_single_heartbeat_detail(request, args, kwargs)
            elif command == "getAllHeartbeatInfo":
                ret = self.get_all_heartbeat_info(request, args, kwargs)
            elif command == "setAutoRestore":
                ret = self.set_auto_restore(request, args, kwargs)
            elif command == "getDoubleControlOverview":
                ret = self.get_double_control_overview(request, args, kwargs)                
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    # 获取新的vrrp_instance的编号，这个编号应用于vrrp_instance的名称和virtual_router_id的编号,从1开始
    def get_new_vi_str_num(self, configInfo):
        try:
            viNums = []
            if "vrrp_instance" not in configInfo.keys():
                rdInt = random.randint(1, 255)
                return str(rdInt)
            for vrrpInstName in configInfo['vrrp_instance'].keys():
                viNum = re.search("\d+", vrrpInstName).group()
                viNums.append(int(viNum))
            if len(viNums) == 0:
                rdInt = random.randint(1, 255)
                return str(rdInt)
            else:
                # 获取一个随机数，并且不是已经使用过的
                while True:
                    rdInt = random.randint(1, 255)
                    if rdInt not in viNums:
                        break
                return str(rdInt)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))

    def rollback_add_local_heartbeat(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
        except Exception as err:
            logger.error(f"rollback_add_local_heartbeat exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def add_local_heartbeat(self, request, role, heartbeatPasswd, viNum):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            localNic = request.data.get('localNic')
            localIp = request.data.get('localIp')
            reqViNum = request.data.get('viNum')

            # 如果后端发起，并且已经给了viNum,那就必须使用一致的viNum
            if reqViNum and requestEnd == "backend":
                viNum = reqViNum

            # 采用ping命令判断对端心跳网卡是否网络通畅
            remoteIp = request.data.get('remoteIp')
            command = f"ping -c 3 -I {localIp} {remoteIp}"
            (status, output) = run_cmd(command)
            if status == 0:
                logger.debug(f"Ping to {remoteIp} successful.")
            else:
                logger.error(f"Ping to {remoteIp} failed.")
                resp = get_error_result("NetworkUnreachable")
                return resp

            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo
            # 2. 根据请求参数，添加新的心跳线路，也即新增一个vrrp_instance实例
            newVrrpInstName = "vrrp_instance vi" + viNum
            notifyMaster = "/etc/keepalived/to_master.sh %s" % newVrrpInstName.split()[-1]
            notifyBackup = "/etc/keepalived/to_backup.sh %s" % newVrrpInstName.split()[-1]            
            newVrrpInst = {
                newVrrpInstName: {
                    'state': role,  # "MASTER"/"BACKUP"
                    'interface': localNic,
                    'unicast_src_ip': localIp,
                    'virtual_router_id': viNum,
                    'priority': '100' if role == "MASTER" else '80',
                    'advert_int': '1',
                    'authentication': {
                        'auth_type': 'PASS',
                        'auth_pass': heartbeatPasswd
                    },
                    'virtual_ipaddress': [],
                    'track_script': [],
                    'notify_master': notifyMaster,
                    'notify_backup': notifyBackup
                }
            }
            # 3. 新增心跳vrrp_instance实例添加到全局变量中
            if 'vrrp_instance' in configInfo.keys():
                configInfo['vrrp_instance'].update(newVrrpInst)
            else:
                configInfo['vrrp_instance'] = newVrrpInst

            # 4. 更新配置文件
            config_info_to_file(configInfo)

            # 5. 重启心跳服务
            restart_service('keepalived')
            
            return resp
        except Exception as e:
            logger.error("call add_local_heartbeat error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def add_remote_heartbeat(self, request, heartbeatPasswd, viNum):
        try:
            resp = get_error_result("Success")
            remoteNic = request.data.get('remoteNic')
            remoteIp = request.data.get('remoteIp')
            localNic = request.data.get('localNic')
            localIp = request.data.get('localIp')

            data = {
                "command": "addHeartbeat",
                "requestEnd": "backend",
                "localNic": remoteNic,
                "localIp": remoteIp,
                "remoteIp": localIp,
                "remoteNic": localNic,
                "heartbeatPasswd": heartbeatPasswd,
                "viNum": viNum
            }
            return peer_post("/cluster/doubleCtlSetting/heartbeat", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_heartbeat(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中添加一个vrrp_instance实例"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            heartbeatPasswd = request.data.get('heartbeatPasswd')

            # 生成随机的心跳线路密码: 请求参数里面有心跳线路密码就直接使用，没有就新生成
            if not heartbeatPasswd:
                heartbeatPasswd = generate_password(12)

            # 生成下一个不重复的vrrp的编号，去掉已经使用过的[1,254]之间的数字
            configInfo = read_config_file_to_dict()
            viNum = self.get_new_vi_str_num(configInfo)

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # a、本地添加心跳
                resp = self.add_local_heartbeat(request, "MASTER", heartbeatPasswd, viNum)
                if resp.get('code') != 0:
                    logger.error("local host add heartbeat failed!!!")
                    return resp

                # b、发起http请求对端机器添加心跳,远程主机默认都是BACKUP角色
                resp = self.add_remote_heartbeat(request, heartbeatPasswd, viNum)
                if resp.get('code') != 0:
                    logger.error("peer host add heartbeat failed!!!")
                    # 回滚本地
                    self.rollback_add_local_heartbeat(request)
                    return resp
            else:
                resp = self.add_local_heartbeat(request, "BACKUP", heartbeatPasswd, viNum)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_update_local_heartbeat(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
        except Exception as err:
            logger.error(f"rollback_update_local_heartbeat exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def update_local_heartbeat(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            localNic = request.data.get('localNic')
            role = request.data.get('role')

            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加新的心跳线路，也即新增一个vrrp_instance实例
            newVrrpInstName = "vrrp_instance vi" + viNum
            notifyMaster = "/etc/keepalived/to_master.sh %s" % newVrrpInstName.split()[-1]
            notifyBackup = "/etc/keepalived/to_backup.sh %s" % newVrrpInstName.split()[-1]
            oldHeartbeatPasswd = configInfo['vrrp_instance'][newVrrpInstName]['authentication']['auth_pass']
            newVrrpInst = {
                newVrrpInstName: {
                    'state': role,  # "MASTER"/"BACKUP"
                    'interface': localNic,
                    'virtual_router_id': viNum,
                    'priority': '100' if role == "MASTER" else '80',
                    'advert_int': '1',
                    'authentication': {
                        'auth_type': 'PASS',
                        'auth_pass': oldHeartbeatPasswd
                    },
                    'virtual_ipaddress': [],
                    'track_script': [],
                    'notify_master': notifyMaster,
                    'notify_backup': notifyBackup
                }
            }
            # 3. 新增心跳vrrp_instance实例添加到全局变量中
            if 'vrrp_instance' in configInfo.keys()():
                configInfo['vrrp_instance'].update(newVrrpInst)
            else:
                configInfo['vrrp_instance'] = newVrrpInst

            # 4. 更新配置文件
            config_info_to_file(configInfo)
            return resp
        except Exception as e:
            logger.error("call add_local_heartbeat error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def update_remote_heartbeat(self, request, role):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            remoteNic = request.data.get('remoteNic')
            role = request.data.get('role')

            data = {
                "command": "updateHeartbeat",
                "requestEnd": "backend",
                "viNum": viNum,
                "localNic": remoteNic,
                "role": 'MASTER' if role == "BACKUP" else 'MASTER'
            }
            return peer_post("/cluster/doubleCtlSetting/heartbeat", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def update_heartbeat(self, request, *args, **kwargs):
        """主要用于更新vrrp_instance实例的角色和优先级：
        用于故障后恢复，故障恢复后的旧Master机器一定要用Backup角色启动，用于备份增量数据"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # a、本地添加心跳
                resp = self.update_local_heartbeat(request)
                if resp.get('code') != 0:
                    logger.error("local host update heartbeat info failed!!!")
                    return resp
                # b、发起http请求对端机器添加心跳,远程主机默认都是BACKUP角色
                resp = self.update_remote_heartbeat(request)
                if resp.get('code') != 0:
                    logger.error("peer host update heartbeat info failed!!!")
                    # 本地回滚
                    self.rollback_update_local_heartbeat(request)
                    return resp
            else:
                resp = self.add_local_heartbeat(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_delete_local_heartbeat(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
        except Exception as err:
            logger.error(f"rollback_delete_local_heartbeat exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def delete_local_heartbeat(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            localNic = request.data.get('localNic')

            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数, 拼接需要删除vrrp_instance实例的name
            deleteVrrpInstName = "vrrp_instance vi" + viNum
            # 3. 删除心跳vrrp_instance实例添加到全局变量中
            if 'vrrp_instance' in configInfo.keys() and deleteVrrpInstName in configInfo['vrrp_instance'].keys():
                configInfo['vrrp_instance'].pop(deleteVrrpInstName)
            else:
                logger.error(''.join(traceback.format_exc()))
                ret = get_error_result("HeartbeatInfoNotExists")
                return JSONResponse(ret)

            # 4. 更新配置文件
            config_info_to_file(configInfo)
            return resp
        except Exception as e:
            logger.error("call add_local_heartbeat error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def delete_remote_heartbeat(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            remoteNic = request.data.get('remoteNic')
            data = {
                "command": "deleteHeartbeat",
                "requestEnd": "backend",
                "viNum": viNum,
                "localNic": remoteNic
            }
            return peer_post("/cluster/doubleCtlSetting/heartbeat", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def delete_heartbeat(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中添加一个vrrp_instance实例"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            localNic = request.data.get('localNic')
            remoteNic = request.data.get('remoteNic')
            localIp = request.data.get('localIp')
            remoteIp = request.data.get('remoteIp')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # a、本地添加心跳
                resp = self.delete_local_heartbeat(request)
                if resp.get('code') != 0:
                    logger.error("local host delete heartbeat failed!!!")
                    return resp                
                # b、发起http请求对端机器添加心跳,远程主机默认都是BACKUP角色
                resp = self.delete_remote_heartbeat(request)
                if resp.get('code') != 0:
                    logger.error("peer host delete heartbeat failed!!!")
                    # 回滚本地
                    self.rollback_delete_local_heartbeat(request)
                    return resp
            else:
                resp = self.delete_local_heartbeat(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def start_heartbeat_service(self, request, *args, **kwargs):
        """启动keepalived服务，需要用户单独web界面点击启动"""
        try:
            resp = get_error_result("Success")
            # 写实际业务逻辑
            cmd = "systemctl start keepalived"
            (status, output) = run_cmd(cmd)
            if status != 0:
                if 'service not found' in output:
                    logger.error("Dual-control service not found!!!")
                    resp = get_error_result("DualControlServiceNotFound")
                else:
                    logger.error("Failed to satrt Dual-control service!!!")
                    resp = get_error_result("StartDualControlServiceError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def stop_heartbeat_service(self, request, *args, **kwargs):
        """关闭keepalived服务，需要用户单独web界面点击启动"""
        try:
            resp = get_error_result("Success")
            # 写实际业务逻辑
            cmd = "systemctl stop keepalived"
            (status, output) = run_cmd(cmd)
            if status != 0:
                if 'service not loaded' in output:
                    logger.error("Dual-control service not found!!!")
                    resp = get_error_result("DualControlServiceNotFound")
                else:
                    logger.error("Failed to stop Dual-control service!!!")
                    resp = get_error_result("StopDualControlServiceError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_local_single_heartbeat_detail(self, request):
        try:
            viNum = request.data.get('viNum')
            localNic = request.data.get('localNic')
            localIp = request.data.get('localIp')

            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 2. 根据请求参数, 拼接数据
            # 获取当前节点hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            data = {
                'pingNode': {},
                'copyLv': {}
            }
            vrrpInstName = "vrrp_instance vi%s" % viNum
            if 'vrrp_instance' not in configInfo.keys() or \
                vrrpInstName not in configInfo['vrrp_instance'].keys():
                return get_error_result("HeartbeatInfoNotExists")
            # 获取配置文件中vrrp实例数据
            vrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            if len(vrrpInst['virtual_ipaddress']):
                vipInfo = vrrpInst['virtual_ipaddress'][0] if len(vrrpInst['virtual_ipaddress']) else ""
                # 判断当前vip网卡是否具有设置的vip，也即是否为keepalived的Master主机
                vip = vipInfo.split("/")[0]
                vipNic = vipInfo.split()[2]
                isOwnVip = check_ip_on_interface(vip, vipNic)
            else:
                vip = ""
                vipNic = ""
                isOwnVip = False

            data = {
                "hostname": localHostname,
                'isOwnVip': isOwnVip,
                "viNum": viNum,
                "vip": vip,
                'vipNic': vipNic,
                'localIp': vrrpInst["unicast_src_ip"],
                'localNic': vrrpInst["interface"],
            }

            # 更新ping节点信息
            # 判断vrrp_instance实例中的check_gataway信息
            gateway = ""
            pingNodeStatus = False
            isPingNodeEnabled = False
            pingNodeScript = 'check_gateway_vi%s' % viNum
            pingNodeInstName = 'vrrp_script %s' % pingNodeScript
            if len(vrrpInst['track_script']) and pingNodeScript in vrrpInst['track_script']:
                isPingNodeEnabled = True
            # 获取检测脚本信息
            if 'vrrp_script' in configInfo.keys() and pingNodeInstName in configInfo['vrrp_script'].keys():
                scriptInst = configInfo['vrrp_script'][pingNodeInstName]
                (vip, gateway) = scriptInst['script'].split()[1:]
                if isOwnVip:
                    # 判断该ping节点vip地址ping网关
                    cmd = "ping -I %s -c 1 %s" % (vip, gateway)
                    (status, output) = run_cmd(cmd)
                    if status == 0:
                        pingNodeStatus = True
                    
            # 把pingNode信息组合到返回数据
            data.update({
                'pingNode': {
                    'gateway': gateway,
                    'pingStatus': pingNodeStatus,
                    'isEnabled': isPingNodeEnabled
                }
            })

            # 更新复制逻辑卷信息
            # 判断vrrp_instance实例中的check_drbd信息
            drbdScriptNameMath = 'check_drbd_vi%s_' % (viNum)
            checkDrbdVrrpScriptArray = []
            if 'vrrp_script' in configInfo.keys() :
                checkDrbdVrrpScriptArray = [e.split()[-1] for e in configInfo['vrrp_script'].keys() if drbdScriptNameMath in e]
            checkDrbdTrackScriptArray = [e for e in vrrpInst['track_script'] if e.startswith(drbdScriptNameMath)]
            copyLv = {}
            data['copyLv'] = {}
            for scriptName in checkDrbdVrrpScriptArray:
                isCheckDrbdEnabled = True if scriptName in checkDrbdTrackScriptArray else False
                # 获取资源名称
                lvName = scriptName.split("_")[-1]
                # 根据资源名，获取drbd对应的配置文件，然后读取配置文件信息
                resFile = "/usr/local/etc/drbd.d/%s.res" % lvName
                resFileExist = os.path.exists(resFile)
                if not resFileExist:
                    logger.debug("The replication logical volume resource file does not exist!")
                    return get_error_result("Success", data)
                cmd = "grep %s %s" % (lvName, resFile)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    logger.error("grep command error!!!")
                    return get_error_result("GrepCmdError")
                diskArray = output.split('\n')[-1]
                vgName = diskArray.split()[-1].split("/")[-2]
                # 执行命令获取资源角色
                getRoleCmd = "drbdadm role %s" % lvName
                (status, role) = run_cmd(getRoleCmd)
                if status != 0:
                    if 'not defined in your config' in role:
                        logger.error("The replication logical volume resource does not exist!!!")
                        #return get_error_result("CopyLvResourceNotExist")
                        role = ""
                    elif 'Unknown resource' in role:
                        logger.error("The replication logical volume resource is not started!!!")
                        #return get_error_result("CopyLvResourceNotStarted")
                        role = ""
                    else:
                        logger.error("Failed to get replication logical volume resource role!!!")
                        #return get_error_result("GetCopyLvResourceRoleError")
                        role = ""
                # 获取cstate资源主备连接状态信息
                (status, cstate) = run_cmd("drbdadm cstate %s" % lvName)
                if status != 0:
                    cstate = ""
                copyLv[vgName+"-"+lvName] = {
                    "cstate": cstate,
                    "role": role,
                    "isEnabled": isCheckDrbdEnabled
                }
                # 数据更新写入到返回数据中
                data['copyLv'].update(copyLv)
            # 2. 返回数据:a、当前心跳线路基本信息; b、持有的双机资源：Vip信息、Ping节点资源信息、复制逻辑卷资源列表信息
            # 配置文件中 基本信息和vip在vrrp_instance都有，
            # ping节点和复制逻辑卷资源在track_script获取script的名称，然后找到对应脚本
            # Ping节点的脚本找到后，解析内容script，信息都有，ping节点的联通状态需要执行ping命令获取
            # 复制逻辑卷的信息，需要找到对应的/usr/local/etc/drbd.d/<resource>.res获取信息：逻辑卷和卷组，角色直接执行命令获取

            {
                'hostname': 'node1',
                'isOwnVip': True,
                'localIp': '192.168.3.11',
                'localNic': 'ens33',
                'pingNode': {
                    'gateway': '192.168.0.1',
                    'status': True
                },
                'copyLv': {
                    'vg1-lv1': 'primary',
                    'vg1-lv2': 'secondary',
                }
            }        
            return get_error_result("Success", data)
        except Exception as e:
            logger.error("call get_all_local_hearbeat_info error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret) 
          
    def get_remote_single_heartbeat_detail(self, request):
        try:
            resp = get_error_result("Success")
            remoteNic = request.data.get('remoteNic')
            remoteIp = request.data.get('remoteIp')
            viNum = request.data.get('viNum')

            data = {
                "command": "getSingleHeartbeatDetail",
                "requestEnd": "backend",
                "localNic": remoteNic,
                "localIp": remoteIp,
                "viNum": viNum,
            }
            return peer_post("/cluster/doubleCtlSetting/heartbeat", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
                
    def get_single_heartbeat_detail(self, request, *args, **kwargs):
        """获取当前节点下所有vrrp_instance实例、获取每个实例对应的脚本控制的双机资源，已经双机资源的状态信息"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    localResp = self.get_local_single_heartbeat_detail(request)
                    if localResp.get('code') != 0:
                        logger.error("local host get heartbeat detail failed!!!")
                        return get_error_result("GetLocalHeartbeatDetailError")
                    localResp = localResp.get('data')
                    # c、组一个心跳线路信息的数组反馈给前端
                    retData = {}
                    retData['localhost'] = localResp['hostname']
                    retData['remotehost'] = remoteHost
                    retData['viNum'] = localResp['viNum']
                    retData['localIp'] = localResp['localIp']
                    retData['localNic'] = localResp['localNic']
                    retData['remoteIp'] = ""
                    retData['remoteNic'] = ""
                    if localResp['isOwnVip']:
                        retData['vip'] = localResp['vip']
                        retData['vipNic'] = localResp['vipNic']
                        retData['vipHost'] = localResp['hostname']
                    else:
                        retData['vip'] = localResp['vip']
                        retData['vipNic'] = localResp['vipNic']
                        retData['vipHost'] = ""

                    if localResp['pingNode']['gateway'] != "":
                        retData['pingNode'] = localResp['pingNode']
                    else:
                        retData['pingNode'] = {
                            'gateway': "",
                            "status": False
                        }
                    retData['copyLv'] = []
                    for copyLvName in localResp['copyLv'].keys():
                        isCopyLvEnabled = True if localResp['copyLv'][copyLvName]["isEnabled"] else False
                        # 判断复制逻辑卷双机资源是否状态正常：只需要在拥有vip的机器判断，状态分为：正常、异常、脱机
                        copyLvDict = {
                            'name': copyLvName,
                            localResp['hostname']: localResp['copyLv'][copyLvName]["role"],
                            remoteHost: "",
                            'cstate': localResp['copyLv'][copyLvName]["cstate"],
                            'isEnabled': isCopyLvEnabled
                        }
                        retData['copyLv'].append(copyLvDict)
                    return get_error_result("Success", retData)

                else:    
                    # a、发起http请求对端机器，获取对端机器所有心跳线路信息
                    remoteResp = self.get_remote_single_heartbeat_detail(request)
                    if remoteResp.get('code') != 0:
                        logger.error("peer host get heartbeat detail failed!!!")
                        return get_error_result("GetPeerHeartbeatDetailError")
                    # b、处理本地，需要使用远程端返回的数据
                    remoteResp = remoteResp.get('data')
                    localResp = self.get_local_single_heartbeat_detail(request)
                    if localResp.get('code') != 0:
                        logger.error("local host get heartbeat detail failed!!!")
                        return get_error_result("GetLocalHeartbeatDetailError")
                    localResp = localResp.get('data')
                    # c、组一个心跳线路信息的数组反馈给前端
                    retData = {}
                    retData['localhost'] = localResp['hostname']
                    retData['remotehost'] = remoteResp['hostname']
                    retData['viNum'] = localResp['viNum']
                    retData['localIp'] = localResp['localIp']
                    retData['localNic'] = localResp['localNic']
                    retData['remoteIp'] = remoteResp['localIp']
                    retData['remoteNic'] = remoteResp['localNic']
                    if remoteResp['isOwnVip']:
                        retData['vip'] = remoteResp['vip']
                        retData['vipNic'] = remoteResp['vipNic']
                        retData['vipHost'] = remoteResp['hostname']
                    elif localResp['isOwnVip']:
                        retData['vip'] = localResp['vip']
                        retData['vipNic'] = localResp['vipNic']
                        retData['vipHost'] = localResp['hostname']
                    else:
                        retData['vip'] = localResp['vip']
                        retData['vipNic'] = localResp['vipNic']
                        retData['vipHost'] = ""

                    if localResp['pingNode']['gateway'] != "":
                        retData['pingNode'] = localResp['pingNode']
                    elif remoteResp['pingNode']['gateway'] != "":
                        retData['pingNode'] = remoteResp['pingNode']
                    else:
                        retData['pingNode'] = {
                            'gateway': "",
                            "status": False
                        }
                    retData['copyLv'] = []
                    for copyLvName in localResp['copyLv'].keys():
                        isCopyLvEnabled = True if localResp['copyLv'][copyLvName]["isEnabled"] and remoteResp['copyLv'][copyLvName]["isEnabled"] else False
                        # 判断复制逻辑卷双机资源是否状态正常：只需要在拥有vip的机器判断，状态分为：正常、异常、脱机
                        copyLvDict = {
                            'name': copyLvName,
                            localResp['hostname']: localResp['copyLv'][copyLvName]["role"],
                            remoteResp['hostname']: remoteResp['copyLv'][copyLvName]["role"],
                            'cstate': localResp['copyLv'][copyLvName]["cstate"],
                            'isEnabled': isCopyLvEnabled
                        }
                        retData['copyLv'].append(copyLvDict)
                    resp = get_error_result("Success", retData)
            else:
                # backend后端发起请求的本地处理
                resp = self.get_local_single_heartbeat_detail(request) 
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def check_heartbeat_pack(self, hbNic, hbIp, multicast_ip=HEARTBEAT_IP, vrrp_proto=112, timeout=2):
        """
        Capture and return a list of unique source IP addresses from VRRP packets.

        :param hbNic: The heartbeat network interface to sniff on.
        :param hbIp: The heartbeat network ip to check.
        :param multicast_ip: The multicast IP address for VRRP packets (default: '224.0.0.88').
        :param vrrp_proto: The protocol number for VRRP packets (default: 112).
        :param timeout: The sniff timeout in seconds (default: 2).
        :return: hbIp wheter in heartbeat ips or not
        """
        unique_ip_set = set()

        def packet_callback(packet):
            if packet.haslayer(IP) and packet[IP].dst == multicast_ip and packet[IP].proto == vrrp_proto:
                src_ip = packet[IP].src
                unique_ip_set.add(src_ip)

        # 开始嗅探，指定网卡、BPF过滤器和回调函数
        sniff(iface=hbNic, filter=f"ip dst {multicast_ip} and proto {vrrp_proto}", prn=packet_callback, store=0, timeout=timeout)
        logger.debug(f"check heartbeat ips: {unique_ip_set}, current heartbeat ip: {hbIp}")
        # 将集合转换为列表并返回
        return (hbIp in unique_ip_set)

    def get_all_local_hearbeat_info(self, request, vrrpInstances):
        try:
            resp = get_error_result("Success")
            # 获取对端请求给的所有vrrp实例的心跳网卡名和IP数据
            peerVrrpInstances = vrrpInstances
            if vrrpInstances is None: 
                # None表示backend请求的，数据放在请求参数中，在get_all_remote_hearbeat_info中实现
                peerVrrpInstances = request.data.get("vrrpInstances")

            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 2. 根据请求参数, 拼接数据
            # 获取当前节点hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            data = {
                "hostname": localHostname,
                'vrrpInstances': {}
            }
            if 'vrrp_instance' not in configInfo.keys():
                return get_error_result("Success", data)
            for elementKey in configInfo['vrrp_instance'].keys():
                vrrpInst = configInfo['vrrp_instance'][elementKey]
                if len(vrrpInst['virtual_ipaddress']):
                    vipInfo = vrrpInst['virtual_ipaddress'][0] if len(vrrpInst['virtual_ipaddress']) else ""
                    # 判断当前vip网卡是否具有设置的vip，也即是否为keepalived的Master主机
                    vip = vipInfo.split("/")[0]
                    vipNic = vipInfo.split()[2]
                    isOwnVip = check_ip_on_interface(vip, vipNic)
                else:
                    vip = ""
                    vipNic = ""
                    isOwnVip = False
                
                # 处理脱机情况
                if not peerVrrpInstances:
                    pingPeerStatus = False
                else:
                    requestEnd = request.data.get('requestEnd')
                    if requestEnd == "backend":
                        peerLocalIp = peerVrrpInstances[elementKey]["unicast_src_ip"]
                    else:
                        peerLocalIp = peerVrrpInstances[elementKey]["localIp"]
                    # 判断本地心跳线路的角色 BACKUP 那么取对端心跳网卡ip
                    masterHeartbeatIp = vrrpInst["unicast_src_ip"]
                    if vrrpInst["state"] == "BACKUP":
                        masterHeartbeatIp = peerLocalIp
                    # 判断该vrrp实例的心跳网卡ping对端是否畅通
                    cmd = "ping -I %s -c 1 %s" % (vrrpInst["unicast_src_ip"], peerLocalIp)
                    (pingStatus, output) = run_cmd(cmd)
                    # 判断keepalived在该心跳线路上面的心跳包是否正常：需要区分角色进行检测，因为心跳只有master端发送
                    localHeartbeatNic = vrrpInst["interface"]
                    logger.debug(f"check hearbeat pack, local nic {localHeartbeatNic}, masterIp {masterHeartbeatIp}")
                    isHeartbeatOk = self.check_heartbeat_pack(localHeartbeatNic, masterHeartbeatIp)
                    pingPeerStatus = False
                    # ping 对端心跳网卡和心跳包都正常，则认为通信是正常的
                    if pingStatus == 0 and isHeartbeatOk:
                        pingPeerStatus = True

                data["vrrpInstances"][elementKey] = {
                    "viNum": vrrpInst["virtual_router_id"],
                    "vip": vip,
                    'vipNic': vipNic,
                    'localIp': vrrpInst["unicast_src_ip"],
                    'localNic': vrrpInst["interface"],
                    'pingPeerStatus': pingPeerStatus,
                    'isOwnVip': isOwnVip,
                }
            
            # 3. 返回的数组数据
            '''
            {
                'hostname': 'node1',
                'vrrpInstances': {
                    'vrrp_instance vi1': {
                        'isOwnVip': True,
                        'vipNic': 'ens36',
                        'localIp': '192.168.3.11',
                        'localNic': 'ens33',
                        'pingPeerStatus': True 
                    },
                    'vrrp_instance vi2': {
                        'isOwnVip': True,
                        'vipNic': 'ens37',
                        'localIp': '192.168.4.11',
                        'localNic': 'ens34',
                        'pingPeerStatus': True 
                    }
                }
            }
            '''
            return get_error_result("Success", data)
        except Exception as e:
            logger.error("call get_all_local_hearbeat_info error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
            
    def get_all_remote_hearbeat_info(self, request):
        """把当前所有vrrp_instance对应实例的心跳网卡-ip都要发送到对端机器，然后对端机器才能进行通信测试"""
        {
            "node2": {
                "vrrp_instance vi1": {
                    'localIp': '192.168.4.11',
                    'localNic': 'ens34'
                },
                "vrrp_instance vi2": {
                    'localIp': '192.168.5.11',
                    'localNic': 'ens34'
                }  
            }
        }
        try:
            resp = get_error_result("Success")
            # 获取本地数据
            configInfo = read_config_file_to_dict()
            # 获取当前所有vrrp实例的本地心跳网卡名和ip地址数据
            vrrpInstances = configInfo["vrrp_instance"] if "vrrp_instance" in configInfo.keys() else {}
            # 组请求数据
            data = {
                "command": "getAllHeartbeatInfo",
                "requestEnd": "backend",
                "vrrpInstances": vrrpInstances
            }
            return peer_post("/cluster/doubleCtlSetting/heartbeat", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
    
    def get_all_heartbeat_info(self, request, *args, **kwargs):
        """双机互相使用心跳网卡设定的ip地址，互相ping通3次，就认为心跳新路是已经连接的状态"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    localResp = self.get_all_local_hearbeat_info(request, None)
                    if localResp.get('code') != 0:
                        logger.error("local host get heartbeat info failed!!!")
                        return localResp
                    localResp = localResp.get('data')
                    # c、组一个心跳线路信息的数组反馈给前端
                    retData = []
                    # 1、处理所有本地有的vrrp_instance
                    for localElementKey in localResp['vrrpInstances'].keys():
                        retVrrpInst = {}
                        localInst = localResp['vrrpInstances'][localElementKey]
                        if localInst['isOwnVip']:
                            vipHost = localResp['hostname']
                            vip = localInst['vip']
                            vipNic = localInst['vipNic']                            
                        else:
                            vipHost = ""
                            vip = ""
                            vipNic = ""                          
                        retVrrpInst = {
                            "viNum": localInst['viNum'],
                            "vip": vip,
                            'vipNic': vipNic,
                            'vipHost':  vipHost,
                            'localIp': localInst["localIp"],
                            'localNic': localInst['localNic'],
                            'localHost': localResp['hostname'],
                            'remoteIp': "",
                            'remoteNic': "",
                            'remoteHost': "",
                            'status': False,
                        }
                        retData.append(retVrrpInst)
                    return get_error_result("Success", retData)

                # a、发起http请求对端机器，获取对端机器所有心跳线路信息
                remoteResp = self.get_all_remote_hearbeat_info(request)
                if remoteResp.get('code') != 0:
                    logger.error("peer host get heartbeat info failed!!!")
                    return remoteResp
                # b、处理本地，需要使用远程端返回的数据
                remoteResp = remoteResp.get('data')
                localResp = self.get_all_local_hearbeat_info(request, remoteResp["vrrpInstances"])
                if localResp.get('code') != 0:
                    logger.error("local host get heartbeat info failed!!!")
                    return localResp
                localResp = localResp.get('data')
                # c、组一个心跳线路信息的数组反馈给前端
                retData = []
                # 1、处理所有本地有的vrrp_instance
                for localElementKey in localResp['vrrpInstances'].keys():
                    retVrrpInst = {}
                    if localElementKey in remoteResp["vrrpInstances"].keys():
                        localInst = localResp['vrrpInstances'][localElementKey]
                        remoteInst = remoteResp['vrrpInstances'][localElementKey]
                        if localInst['isOwnVip']:
                            vipHost = localResp['hostname']
                            vip = localInst['vip']
                            vipNic = localInst['vipNic']
                        elif remoteInst['isOwnVip']:
                            vipHost = remoteResp['hostname']
                            vip = remoteInst['vip']
                            vipNic = remoteInst['vipNic']                            
                        else:
                            vipHost = ""
                            vip = localInst['vip']
                            vipNic = localInst['vipNic']

                        if localInst['pingPeerStatus'] and remoteInst['pingPeerStatus']:
                            status = True
                        else:
                            status = False
                        retVrrpInst = {
                            "viNum": localInst['viNum'],
                            "vip": vip,
                            'vipNic': vipNic,
                            'vipHost':  vipHost,
                            'localIp': localInst["localIp"],
                            'localNic': localInst['localNic'],
                            'localHost': localResp['hostname'],
                            'remoteIp': remoteInst['localIp'],
                            'remoteNic': remoteInst['localNic'],
                            'remoteHost': remoteResp['hostname'],
                            'status': status,
                        }
                    else:
                        # 远程没有这个vrrp_instance实例
                        localInst = localResp['vrrpInstances'][localElementKey]
                        if localInst['isOwnVip']:
                            vipHost = localResp['hostname']
                            vip = localInst['vip']
                            vipNic = localInst['vipNic']                            
                        else:
                            vipHost = ""
                            vip = ""
                            vipNic = ""                          
                        retVrrpInst = {
                            "viNum": localInst['viNum'],
                            "vip": vip,
                            'vipNic': vipNic,
                            'vipHost':  vipHost,
                            'localIp': localInst["localIp"],
                            'localNic': localInst['localNic'],
                            'localHost': localResp['hostname'],
                            'remoteIp': "",
                            'remoteNic': "",
                            'remoteHost': "",
                            'status': False,
                        }
                    retData.append(retVrrpInst)
                # 2、处理在本地没有的vrrp_instance,但是在远程有的
                for remoteElementKey in remoteResp['vrrpInstances'].keys():
                    if remoteElementKey in localResp['vrrpInstances'].keys():
                        continue
                    retVrrpInst = {}
                    remoteInst = remoteResp['vrrpInstances'][remoteElementKey]
                    vip = remoteInst['vip']
                    vipNic = remoteInst['vipNic']
                    if remoteInst['isOwnVip']:
                        vipHost = remoteInst['hostname']
                    else:
                        vipHost = ""
                    retVrrpInst = {
                        "viNum": remoteInst['viNum'],
                        "vip": vip,
                        'vipNic': vipNic,
                        'vipHost':  vipHost,
                        'localIp': "",
                        'localNic': "",
                        'localHost': "",
                        'remoteIp': remoteInst["localIp"],
                        'remoteNic': remoteInst['localNic'],
                        'remoteHost': remoteInst.get('hostname', ''),
                        'status': False,
                    }
                    retData.append(retVrrpInst)
                return get_error_result("Success", retData)
            else:
                # backend后端发起请求的本地处理
                return self.get_all_local_hearbeat_info(request, None)            
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_set_local_auto_restore(self, request):
        try:
            # 回滚数据库数据
            clusterNode = self.cacheData.get('clusterNode')
            if clusterNode:
                clusterNode.save()
        except Exception as err:
            logger.error(f"rollback_set_local_auto_restore exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def set_local_auto_restore(self, request):
        try:
            resp = get_error_result("Success")
            isEnableAutoRestore = request.data.get('isEnableAutoRestore')
            # 更新数据库记录
            clusterNode = ClusterNode.objects.first()
            if clusterNode:
                # 备份用于回滚
                self.cacheData['clusterNode'] = clusterNode

                updateValue = 1 if isEnableAutoRestore else 0
                clusterNode.is_auto_restore = updateValue
                clusterNode.save()
                logger.info(f"update is_auto_restore to updateValue ")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
    
    def set_remote_auto_restore(self, request):
        try:
            resp = get_error_result("Success")
            isEnableAutoRestore = request.data.get('isEnableAutoRestore')
            data = {
                "command": "setAutoRestore",
                "requestEnd": "backend",
                "isEnableAutoRestore": isEnableAutoRestore
            }
            return peer_post("/cluster/doubleCtlSetting/heartbeat", data)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
    
    def set_auto_restore(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    localResp = self.set_local_auto_restore(request)
                    if localResp.get('code') != 0:
                        logger.error("local host set auto restore failed!!!")
                        return localResp
                else:
                    # a、处理本地机器
                    localResp = self.set_local_auto_restore(request)
                    if localResp.get('code') != 0:
                        logger.error("local host set auto restore failed!!!")
                        return localResp                   
                    # b、发起http请求对端机器
                    remoteResp = self.set_remote_auto_restore(request)
                    if remoteResp.get('code') != 0:
                        logger.error("peer host set auto restore failed!!!")
                        # 本地回滚
                        self.rollback_set_local_auto_restore(request)
                        return remoteResp
                   
                return get_error_result("Success")
            else:
                # backend后端发起请求的本地处理
                return self.set_local_auto_restore(request)            
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
    
    def get_double_control_overview(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            # 获取数据库信息
            peerInfo = ClusterNode.objects.values("ip", "host_name", "status", "double_control_status", "is_auto_restore").first()
            if not peerInfo:
                peerInfo = {"ip": "", "host_name": "", "status": -1, "double_control_status": "singleNode", "is_auto_restore": False}
            # 读取双控配置，获取心跳线路信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            allDrbdTrackScriptArr = []
            abnormalDrbdTrackScriptArr = []
            if 'vrrp_instance' in configInfo.keys():
                # 1、获取所有已添加的复制逻辑卷双机资源
                drbdScriptNameMath = 'check_drbd_'
                # 获取所有vrrp_script信息，也即总复制逻辑卷双控资源
                if 'vrrp_script' in configInfo.keys() :
                    allDrbdTrackScriptArr = [e.split()[-1] for e in configInfo['vrrp_script'].keys() if drbdScriptNameMath in e]
                allDrbdTrackScriptArr = [e for e in allDrbdTrackScriptArr if drbdScriptNameMath in e]                
                # 2、获取所有已经设置了高可用的复制逻辑卷
                # 获取所有track_script信息：注意这里可能包括了监控ping节点资源的
                allCheckDrbdVrrpScriptArr = []
                for elementKey in configInfo['vrrp_instance'].keys():
                    vrrpInst = configInfo['vrrp_instance'][elementKey]
                    allCheckDrbdVrrpScriptArr.extend(vrrpInst['track_script'])
                # 过滤掉Ping节点双机资源
                allCheckDrbdVrrpScriptArr = [e for e in allCheckDrbdVrrpScriptArr if e.startswith(drbdScriptNameMath)]
                # 3、判断复制逻辑卷资源是否正常的高可用运行
                for scriptName in allDrbdTrackScriptArr:
                    isCheckDrbdEnabled = True if scriptName in allCheckDrbdVrrpScriptArr else False
                    # 没有启用高可用，认为是异常
                    if not isCheckDrbdEnabled:
                        abnormalDrbdTrackScriptArr.append(scriptName)
                        continue
                    # 获取资源名称
                    lvName = scriptName.split("_")[-1]
                    # 执行命令获取资源角色
                    getRoleCmd = "drbdadm role %s" % lvName
                    (status, copyLvRole) = run_cmd(getRoleCmd)
                    if status != 0:
                        if 'not defined in your config' in copyLvRole:
                            logger.error("The replication logical volume resource does not exist!!!")
                            copyLvRole = ""
                        elif 'Unknown resource' in copyLvRole:
                            logger.error("The replication logical volume resource is not started!!!")
                            copyLvRole = ""
                        else:
                            logger.error("Failed to get replication logical volume resource role!!!")
                            copyLvRole = ""
                    # 获取cstate资源主备连接状态信息
                    (status, cstate) = run_cmd("drbdadm cstate %s" % lvName)
                    if status != 0:
                        cstate = ""
                    # 如果当前复制逻辑卷资源的role和当前机器心跳线路的role是一致的，并且复制逻辑卷资源是“connected”，那认为是正常资源
                    # 获取当前复制逻辑卷资源所在的心跳线路的role：先获取心跳网卡名，再拼接vrrp_instance实例名，最后获取心跳线路role
                    viName = scriptName.split("_")[2]
                    vrrpInstName = "vrrp_instance %s" % viName
                    heartbeatRole = configInfo['vrrp_instance'][vrrpInstName]['state']
                    isTrueCopyLvDirect = False
                    if heartbeatRole.upper() == "MASTER" and copyLvRole.lower() == "primary":
                        isTrueCopyLvDirect = True
                    elif heartbeatRole.upper() == "BACKUP" and copyLvRole.lower() == "secondary":
                        isTrueCopyLvDirect = True
                    else:
                        isTrueCopyLvDirect = False
                    if not isTrueCopyLvDirect or cstate.lower() != "connected":
                        abnormalDrbdTrackScriptArr.append(scriptName)
                    
            # 读取添加的双控资源：复制逻辑卷信息
            retData = {
                'doubleControlStatus': peerInfo["double_control_status"],
                'isAutoRestore': peerInfo["is_auto_restore"],
                'sumCopyLvCnt': len(allDrbdTrackScriptArr),
                'abnormalCopyLvCnt': len(abnormalDrbdTrackScriptArr)
            }
            return get_error_result("Success", retData)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp


class VirtualIpCmd(Enum):
    AddVirtualIp = "addVirtualIp"
    DeleteVirtualIp = "deleteVirtualIp"
    UpdateVirtualIp = "updateVirtualIp"
    AlterVirtualIpRole = "alterVirtualIpRole"


class VirtualIpView(APIView):
    """虚拟IP管理"""
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in VirtualIpCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'vip': openapi.Schema(type=openapi.TYPE_STRING),
            'submask': openapi.Schema(type=openapi.TYPE_STRING),
            'vipLocalNic': openapi.Schema(type=openapi.TYPE_STRING),
            'vipRemoteNic': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteHeartbeatNic': openapi.Schema(type=openapi.TYPE_STRING),
            'localHeartbeatNic': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command == "addVirtualIp":
                ret = self.add_vitual_ip(request, args, kwargs)
            elif command == "deleteVirtualIp":
                ret = self.delete_vitual_ip(request, args, kwargs)
            elif command == "updateVirtualIp":
                ret = self.update_vitual_ip(request, args, kwargs)                
            elif command == "alterVirtualIpRole":
                ret = self.alter_vip_role(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

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

    def rollback_add_local_vitual_ip(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
        except Exception as err:
            logger.error(f"rollback_add_local_vitual_ip exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def add_local_vitual_ip(self, request):
        try:
            resp = get_error_result("Success")
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            submask = request.data.get('submask')
            vipLocalNic = request.data.get('vipLocalNic')

            # 判断vip是否在本地节点上已经被使用
            usedIps = get_ipv4_addresses()
            if vip in usedIps:
                logger.error("vitual ip already exists on localhost !!!")
                return get_error_result("VipAlreadyExists")
            
            # 判断vip是否已经存在，已经存在则禁止重复使用
            allVips = []
            configInfo = read_config_file_to_dict()
            if configInfo and 'vrrp_instance' in configInfo.keys():
                for vrrpInstName in configInfo['vrrp_instance']:
                    allVips.extend(configInfo['vrrp_instance'][vrrpInstName]['virtual_ipaddress'])
            allVips = [e.split('/')[0] for e in allVips]                    
            if vip in allVips:
                logger.error("vitual ip already exists!!!")
                return get_error_result("VipAlreadyExists")
            
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加vip: 找到对应vrrp_instance，然后更新里面的"virtual_ipaddress"
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            vipInfo = "%s/%s dev %s" % (vip, netaddr.IPAddress(
                submask).netmask_bits(), vipLocalNic)
            updatedVrrpInst["virtual_ipaddress"] = [vipInfo]
            # 3. 新增VIP更新到变量中
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            if self.get_service_status("keepalived")['status'] == "running":
                reloadCmd = "systemctl reload keepalived"
                (status, output) = run_cmd(reloadCmd)
                if status != 0:
                    if 'service not found' in output:
                        logger.error("Dual-control service not found!!!")
                        resp = get_error_result("DualControlServiceNotFound")
                    else:
                        logger.error("Failed to reload dual-control service!!!")
                        resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call add_local_heartbeat error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def add_remote_vitual_ip(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            submask = request.data.get('submask')
            vipRemoteNic = request.data.get('vipRemoteNic')
            data = {
                "command": "addVirtualIp",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "submask": submask,
                "vipLocalNic": vipRemoteNic,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/virtualIp", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_vitual_ip(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中对应vrrp_instance实例配置中添加vip配置"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # a、本地添加VIP
                resp = self.add_local_vitual_ip(request)
                if resp.get('code') != 0:
                    logger.error("local host add vitual ip failed!!!")
                    return resp
                
                # b、发起http请求对端机器添加VIP
                resp = self.add_remote_vitual_ip(request)
                if resp.get('code') != 0:
                    logger.error("peer host add vitual ip failed!!!")
                    # 本地回滚
                    self.rollback_add_local_vitual_ip(request)
                    return resp

            else:
                resp = self.add_local_vitual_ip(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_delete_local_vitual_ip(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
        except Exception as err:
            logger.error(f"rollback_delete_local_vitual_ip exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def delete_local_vitual_ip(self, request):
        try:
            resp = get_error_result("Success")
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加vip: 找到对应vrrp_instance，然后更新里面的"virtual_ipaddress"
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            updatedVrrpInst["virtual_ipaddress"] = []
            # 3. 新增VIP更新到变量中
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            if self.get_service_status("keepalived")['status'] == "running":
                reloadCmd = "systemctl reload keepalived"
                (status, output) = run_cmd(reloadCmd)
                if status != 0:
                    if 'service not found' in output:
                        logger.error("Dual-control service not found!!!")
                        resp = get_error_result("DualControlServiceNotFound")
                    else:
                        logger.error("Failed to reload dual-control service!!!")
                        resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call add_local_heartbeat error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def delete_remote_vitual_ip(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            data = {
                "command": "deleteVirtualIp",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/virtualIp", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def delete_vitual_ip(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中对应vrrp_instance实例配置中删除vip配置"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # b、本地添加VIP
                resp = self.delete_local_vitual_ip(request)
                if resp.get('code') != 0:
                    logger.error("local host delete vitual ip failed!!!")
                    return resp
                
                # a、发起http请求对端机器添加VIP
                resp = self.delete_remote_vitual_ip(request)
                if resp.get('code') != 0:
                    logger.error("peer host delete vitual ip failed!!!")
                    # 本地回滚
                    self.rollback_delete_local_vitual_ip(request)
                    return resp

            else:
                resp = self.delete_local_vitual_ip(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_update_local_vitual_ip(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
        except Exception as err:
            logger.error(f"rollback_update_local_vitual_ip exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def update_local_vitual_ip(self, request):
        try:
            resp = get_error_result("Success")
            oldVip = request.data.get('oldVip')
            newVip = request.data.get('newVip')

            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 1. 先把virtual_ipaddress字段内容替换掉
            # 把其他用到了vip的字段内容替换掉
            changeOtherVipCmd = "set -i 's/%s/%s/g' %s" % (oldVip, newVip, HEARTBEAT_CONFIG_FILE_PATH)
            (status, output) = run_cmd(changeOtherVipCmd)
            if status != 0:
                logger.error("Failed to update virtual IP!!!")
                resp = get_error_result("UpdateVipError")
            return resp
        except Exception as err:
            logger.error(f"call update_local_vitual_ip error: {err}")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def update_remote_vitual_ip(self, request):
        try:
            resp = get_error_result("Success")
            oldVip = request.data.get('oldVip')
            newVip = request.data.get('newVip')
            data = {
                "command": "updateVirtualIp",
                "requestEnd": "backend",
                "oldVip": oldVip,
                "newVip": newVip
            }
            return peer_post("/cluster/doubleCtlSetting/virtualIp", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def update_vitual_ip(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中对应vrrp_instance实例配置中删除vip配置"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # a、本地添加VIP
                resp = self.update_local_vitual_ip(request)
                if resp.get('code') != 0:
                    logger.error("local host delete vitual ip failed!!!")
                    return resp
                # b、发起http请求对端机器
                resp = self.update_remote_vitual_ip(request)
                if resp.get('code') != 0:
                    logger.error("peer host delete vitual ip failed!!!")
                    # 本地回滚
                    self.rollback_update_local_vitual_ip(request)
                    return resp
            else:
                resp = self.update_local_vitual_ip(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_alter_local_vip_role(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            if self.get_service_status("keepalived")['status'] == "running":
                reloadCmd = "systemctl reload keepalived"
                run_cmd(reloadCmd)
        except Exception as err:
            logger.error(f"rollback_update_local_vitual_ip exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def alter_local_vip_role(self, request):
        try:
            resp = get_error_result("Success")
            role = request.data.get('role')
            viNum = request.data.get('viNum')
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加vip: 找到对应vrrp_instance，然后更新里面的"virtual_ipaddress"
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            updatedVrrpInst["state"] = role
            updatedVrrpInst["priority"] = '100' if role == "MASTER" else '80'
            # 3. 新增VIP更新到变量中
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            if self.get_service_status("keepalived")['status'] == "running":
                reloadCmd = "systemctl reload keepalived"
                (status, output) = run_cmd(reloadCmd)
                if status != 0:
                    if 'service not found' in output:
                        logger.error("Dual-control service not found!!!")
                        resp = get_error_result("DualControlServiceNotFound")
                    else:
                        logger.error("Failed to reload dual-control service!!!")
                        resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call add_local_heartbeat error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def alter_remote_vip_role(self, request):
        try:
            resp = get_error_result("Success")
            role = request.data.get('role')
            viNum = request.data.get('viNum')
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            data = {
                "command": "alterVirtualIpRole",
                "requestEnd": "backend",
                "viNum": viNum,
                "role": "MASTER" if role == "BACKUP" else "BACKUP",
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/virtualIp", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def alter_vip_role(self, request, *args, **kwargs):
        """切换MASTER/BACKUP，priority都设置为100"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            viNum = request.data.get('viNum')
            localHeartbeatNic = request.data.get('localHeartbeatNic')

            # 判断是已经关闭了所有双机资源的高可用
            configInfo = read_config_file_to_dict()
            vrrpInstName = "vrrp_instance vi" + viNum
            vrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            if vrrpInst["track_script"]:
                resp = get_error_result("ExsitsHaResource")
                logger.error("Exsits ha resource, can't alter vitual ip role!!!")
                return resp
            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # b、本地切换VIP的role
                resp = self.alter_local_vip_role(request)
                if resp.get('code') != 0:
                    logger.error("local host alter vitual ip role failed!!!")
                    return resp
                # a、发起http请求对端机器切换VIP的role
                resp = self.alter_remote_vip_role(request)
                if resp.get('code') != 0:
                    logger.error("peer host alter vitual ip role failed!!!")
                    # 本地回滚
                    self.rollback_alter_local_vip_role(request)
                    return resp

            else:
                resp = self.alter_local_vip_role(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp


class PingNodeCmd(Enum):
    AddPingNode = "addPingNode"
    DeletePingNode = "deletePingNode"
    DisablePingNode = "disablePingNode"
    EnablePingNode = "enablePingNode"    


class PingNodeView(APIView):
    """Ping节点管理"""
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in PingNodeCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'vip': openapi.Schema(type=openapi.TYPE_STRING),
            'pingNodeIp': openapi.Schema(type=openapi.TYPE_STRING),
            'localHeartbeatNic': openapi.Schema(type=openapi.TYPE_STRING),            
            'remoteHeartbeatNic': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command == "addPingNode":
                ret = self.add_ping_node(request, args, kwargs)
            elif command == "deletePingNode":
                ret = self.delete_ping_node(request, args, kwargs)
            elif command == "disablePingNode":
                ret = self.disable_ping_node(request, args, kwargs)
            elif command == "enablePingNode":
                ret = self.enable_ping_node(request, args, kwargs)                                
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def rollback_add_local_ping_node(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_add_local_ping_node exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def add_local_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            pingNodeIp = request.data.get('pingNodeIp')

            # 根据ping命令：判断ping的IP地址是否有效
            allLocalIps = get_ipv4_addresses()
            if vip in allLocalIps:
                command = f"ping -c 3 -I {vip} {pingNodeIp}"
                (status, output) = run_cmd(command)
                if status == 0:
                    logger.debug(f"Ping to {pingNodeIp} successful.")
                else:
                    logger.error(f"Ping to {pingNodeIp} failed.")
                    resp = get_error_result("NetworkUnreachable")
                    return resp

            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加ping node
            vrrpScriptName = "vrrp_script check_gateway_vi" + viNum
            scriptInfo = "/etc/keepalived/check_gateway.sh %s %s" % (vip, pingNodeIp)
            newVrrpScript = {
                "script": scriptInfo,
                "interval": "10"
            }
            # 3. 新增ping node更新到变量中
            if "vrrp_script" not in configInfo.keys():
                configInfo['vrrp_script'] = {}
            # 判断：一条心跳线路只允许添加一个Ping节点资源
            if vrrpScriptName in configInfo['vrrp_script'].keys():
                logger.error("Only one Ping node resource is allowed to be added to a heartbeat line!!!")
                return get_error_result("OneHeartbeatOnePingNode")
            configInfo['vrrp_script'].update({vrrpScriptName: newVrrpScript})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if  serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call add_local_ping_node error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def add_remote_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            pingNodeIp = request.data.get('pingNodeIp')
            data = {
                "command": "addPingNode",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "pingNodeIp": pingNodeIp,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/pingNode", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_ping_node(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中添加对应ping节点的脚本用于本机的健康检查,
        只需要添加在keepalived的master上，自动后端对比两台主机的优先权
        如果心跳网卡是直连的，那么ping节点的功能就可有可无，ping网关无法检测闹裂，，所以直接改为从vip去ping网关"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # a、本地添加ping node
                resp = self.add_local_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("local host add ping node failed!!!")
                    return resp                                
                # b、发起http请求对端机器添加ping node
                resp = self.add_remote_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("peer host add ping node failed!!!")
                    # 本地回滚
                    return resp
            else:
                resp = self.add_local_ping_node(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_delete_local_ping_node(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_delete_local_ping_node exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def delete_local_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加ping node
            vrrpScriptName = "vrrp_script check_gateway_vi" + viNum
            # 3. 删除ping node更新到变量中
            configInfo['vrrp_script'].pop(vrrpScriptName)
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if  serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call delete_local_ping_node error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def delete_remote_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            pingNodeIp = request.data.get('pingNodeIp')
            data = {
                "command": "deletePingNode",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "pingNodeIp": pingNodeIp,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/pingNode", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def delete_ping_node(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中删除对应ping节点的脚本用于本机的健康检查"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # b、本地添加ping node
                resp = self.delete_local_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("local host delete ping node failed!!!")
                    return resp                
                # a、发起http请求对端机器添加ping node
                resp = self.delete_remote_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("peer host delete ping node failed!!!")
                    # 本地回滚
                    self.rollback_delete_local_ping_node(request)
                    return resp
            else:
                resp = self.delete_local_ping_node(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_enable_local_ping_node(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_enable_local_ping_node exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def enable_local_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，启用ping node
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            scriptInfo = "check_gateway_vi" + viNum
            updatedVrrpInst["track_script"].append(scriptInfo)
            # 3. 新增ping node脚本信息更新到变量中
            if "vrrp_instance" not in configInfo.keys():
                configInfo['vrrp_instance'] = {}
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if  serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call enable_local_ping_node error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def enable_remote_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            pingNodeIp = request.data.get('pingNodeIp')
            data = {
                "command": "enablePingNode",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "pingNodeIp": pingNodeIp,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/pingNode", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def enable_ping_node(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中删除对应ping节点的脚本用于本机的健康检查"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                vip = request.data.get('vip')
                vipNic = request.data.get('vipNic')
                # 判断：如果vip所在节点不是primary则不可以启用
                if not vip or not vipNic:
                    logger.error("The current node does not have VIP!!!")
                    return get_error_result("CurrentNodeNotHaveVip")
                isOwnVip = check_ip_on_interface(vip, vipNic)
                if not isOwnVip:
                    logger.error("The current node does not have VIP!!!")
                    return get_error_result("CurrentNodeNotHaveVip")

                # b、本地禁用ping node
                resp = self.enable_local_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("local host enable ping node failed!!!")
                    return resp
                # a、发起http请求对端机器添加ping node
                resp = self.enable_remote_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("peer host enable ping node failed!!!")
                    # 本地回滚
                    self.rollback_enable_local_ping_node(request)
                    return resp
            else:
                resp = self.enable_local_ping_node(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_disable_local_ping_node(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_disable_local_ping_node exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def disable_local_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加ping node
            vrrpScriptName = "check_gateway_vi" + viNum
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            updatedVrrpInst["track_script"].remove(vrrpScriptName)
            # 3. 新增VIP更新到变量中
            if "vrrp_instance" not in configInfo.keys():
                configInfo['vrrp_instance'] = {}
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if  serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")
            return resp
        except Exception as e:
            logger.error("call disable_local_ping_node error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def disable_remote_ping_node(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            pingNodeIp = request.data.get('pingNodeIp')
            data = {
                "command": "disablePingNode",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "pingNodeIp": pingNodeIp,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/pingNode", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def disable_ping_node(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中禁用对应ping节点的脚本用于本机的健康检查"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # b、本地禁用ping node
                resp = self.disable_local_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("local host disable ping node failed!!!")
                    return resp

                # a、发起http请求对端机器添加ping node
                resp = self.disable_remote_ping_node(request)
                if resp.get('code') != 0:
                    logger.error("peer host disable ping node failed!!!")
                    # 本地回滚
                    self.rollback_disable_local_ping_node(request)
                    return resp
            else:
                resp = self.disable_local_ping_node(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp


class CopyLvCmd(Enum):
    AddCopyLv = "addCopyLv"
    DeleteCopyLv = "deleteCopyLv"
    DisableCopyLv = "disableCopyLv"
    EnableCopyLv = "enableCopyLv" 


class CopyLvView(APIView):
    """复制逻辑卷管理"""
    def __init__(self):
        # 实例变量
        self.cacheData = {}
            
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in CopyLvCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'vip': openapi.Schema(type=openapi.TYPE_STRING),
            'vgName': openapi.Schema(type=openapi.TYPE_STRING),
            'lvName': openapi.Schema(type=openapi.TYPE_STRING),
            'localHeartbeatNic': openapi.Schema(type=openapi.TYPE_STRING),            
            'remoteHeartbeatNic': openapi.Schema(type=openapi.TYPE_STRING),
            'drbdDevicePath': openapi.Schema(type=openapi.TYPE_STRING),
            'mountPointPath': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command == "addCopyLv":
                ret = self.add_copy_lv(request, args, kwargs)
            elif command == "deleteCopyLv":
                ret = self.delete_copy_lv(request, args, kwargs)
            elif command == "disableCopyLv":
                ret = self.disable_copy_lv(request, args, kwargs)
            elif command == "enableCopyLv":
                ret = self.enable_copy_lv(request, args, kwargs)                                
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def rollback_add_local_copy_lv(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 回滚脚本：这里直接删除即可
            scriptFile = self.cacheData('scriptFile')
            if scriptFile and os.path.exists(scriptFile):
                os.remove(scriptFile)
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_add_local_copy_lv exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def add_local_copy_lv(self, request, mountPointPath=""):
        try:
            resp = get_error_result("Success")
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            lvName = request.data.get('lvName')
            drbdDevicePath = request.data.get('drbdDevicePath')
            if mountPointPath == "":
                mountPointPath = request.data.get('mountPointPath')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加ping node
            vrrpScriptName = "vrrp_script check_drbd_vi%s_%s" % (viNum, lvName)
            scriptInfo = "/etc/keepalived/check_drbd.sh %s %s" % (vip, lvName)
            newVrrpScript = {
                "script": scriptInfo,
                "interval": "10"
            }
            # 3. 新增ping node更新到变量中
            if "vrrp_script" not in configInfo.keys():
                configInfo['vrrp_script'] = {}
            # 去重判断
            if vrrpScriptName in configInfo['vrrp_script'].keys():
                logger.error("The dual-machine resource already exists!!!")
                return get_error_result("DualMachineResAlreadyExists")
            configInfo['vrrp_script'].update({vrrpScriptName: newVrrpScript})
            # 4. 更新配置文件
            config_info_to_file(configInfo)

            # 5. 在/etc/keepalived/to_master/下面添加一个故障转移的drbd切换脱机primary运行脚本
            scriptContent = [
                "#!/bin/bash",
                "resName=%s" % lvName,
                "datetime=`date \"+%Y-%m-%d\"`",
                "logFile=" + DOUBLE_CONTROL_LOG_PATH + "/to_master_${resName}.log.${datetime}",
                "dateTime=`date \"+%Y-%m-%d %H:%M:%S\"`",
                "echo \"[${dateTime}]: starting drbd ${resName} handler...\" >> $logFile",
                "drbdadm down ${resName}",
                "drbdadm up ${resName}",
                "drbdadm disconnect ${resName}",
                "drbdadm primary --force ${resName}"
            ]
            # mount默认注释行
            if mountPointPath == "":
                mountPointPath = get_device_mountpoint(drbdDevicePath)
            # 由于drbd虚拟盘只在“primary”节点挂载，所以必须每个机器进行实际判断是否挂载
            mountContent = "#mount"
            if mountPointPath != "":
                mountContent = "mount %s %s" % (drbdDevicePath, mountPointPath)
            # 追加mount这行内容
            scriptContent.append(mountContent)
            scriptTailContent = [
                "dateTime=`date \"+%Y-%m-%d %H:%M:%S\"`",
                "echo \"[${dateTime}]: end drbd ${resName} handler.\" >> $logFile",
            ]
            scriptContent.extend(scriptTailContent)
            scriptDir = "/etc/keepalived/to_master/"
            os.makedirs(scriptDir, exist_ok=True)
            scriptContent = "\n".join(scriptContent)
            scriptFile = scriptDir + "drbd_" + lvName + ".sh"
            with open(scriptFile, 'w') as file:
                file.write(scriptContent)
                # 添加shell脚本的执行权限
                os.chmod(scriptFile, 0o755)
                # 备份文件名，用于回滚
                self.cacheData['scriptFile'] = scriptFile

            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if  serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")      
            # 处理返回数据 
            resp = {
                "mountPointPath": mountPointPath
            }
            # 把虚拟盘的挂载路径返回给其他节点
            return get_error_result("Success", resp)
        except Exception as e:
            logger.error("call add_local_copy_lv error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def add_remote_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            mountPointPath = request.data.get('mountPointPath')
            drbdDevicePath = request.data.get('drbdDevicePath')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            lvName = request.data.get('lvName')
            if mountPointPath == "":
                mountPointPath = get_device_mountpoint(drbdDevicePath)            
            data = {
                "command": "addCopyLv",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "lvName": lvName,
                "localHeartbeatNic": remoteHeartbeatNic,
                "mountPointPath": mountPointPath,
                "drbdDevicePath": drbdDevicePath
            }
            return peer_post("/cluster/doubleCtlSetting/copyLv", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_copy_lv(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中添加对应ping节点的脚本用于本机的健康检查,
        只需要添加在keepalived的master上，自动后端对比两台主机的优先权
        如果心跳网卡是直连的，那么ping节点的功能就可有可无，ping网关无法检测闹裂，，所以直接改为从vip去ping网关"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    logger.error("The peer node is not connected!!!")
                    return get_error_result("PeerNodeNotConnected")
                else:                
                    # a、发起http请求对端机器添加ping node
                    resp = self.add_remote_copy_lv(request)
                    if resp.get('code') != 0:
                        logger.error("peer host add_local_copy_lv failed!!!")
                        return resp
                    mountPointPath = resp.get('data')["mountPointPath"]
                    # b、本地添加ping node
                    resp = self.add_local_copy_lv(request, mountPointPath)
                    if resp.get('code') != 0:
                        logger.error("local host add_local_copy_lv failed!!!")
                        # 对端回滚
                        self.delete_remote_copy_lv(request)
                        return resp
            else:
                resp = self.add_local_copy_lv(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_delete_local_copy_lv(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 回滚脚本
            scriptFile = self.cacheData('scriptFile')
            if scriptFile:
                with open(scriptFile, 'w') as f:
                    f.write(self.cacheData['scriptFile'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_delete_local_copy_lv exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def delete_local_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            lvName = request.data.get('lvName')
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加ping node
            vrrpScriptName = "vrrp_script check_drbd_vi%s_%s" % (viNum, lvName)
            # 3. 删除ping node更新到变量中
            configInfo['vrrp_script'].pop(vrrpScriptName)
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")                  
            # 5. 删除to_master下面的drbd资源切换脚本文件
            scriptDir = "/etc/keepalived/to_master/"
            scriptFile = scriptDir + "drbd_" + lvName + ".sh"
            if os.path.exists(scriptFile):
                # 备份文件数据，用于回滚
                with open(scriptFile, 'r') as f:
                    self.cacheData['scriptFile'] = f.read()
                # 删除文件
                os.remove(scriptFile)

            return resp
        except Exception as e:
            logger.error("call delete_local_copy_lv error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def delete_remote_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            lvName = request.data.get('lvName')
            data = {
                "command": "deleteCopyLv",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "lvName": lvName,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/copyLv", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def delete_copy_lv(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中删除对应ping节点的脚本用于本机的健康检查"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    return self.delete_local_copy_lv(request)
                else:
                    # a、本地添加ping node
                    resp = self.delete_local_copy_lv(request)       
                    if resp.get('code') != 0:
                        logger.error("local host delete_local_copy_lv failed!!!")
                        return resp

                    # b、发起http请求对端机器添加ping node
                    resp = self.delete_remote_copy_lv(request)
                    if resp.get('code') != 0:
                        logger.error("peer host delete_local_copy_lv failed!!!")
                        # 本地回滚
                        self.rollback_delete_local_copy_lv(request)
                        return resp
            else:
                resp = self.delete_local_copy_lv(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_enable_local_copy_lv(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_enable_local_copy_lv exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def enable_local_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            lvName = request.data.get('lvName')
            
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，启用ping node
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            scriptInfo = "check_drbd_vi%s_%s" % (viNum, lvName)
            updatedVrrpInst["track_script"].append(scriptInfo)
            # 3. 新增ping node脚本信息更新到变量中
            if "vrrp_instance" not in configInfo.keys():
                configInfo['vrrp_instance'] = {}            
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if  serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")      
            return resp        
        except Exception as e:
            logger.error("call enable_local_copy_lv error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def enable_remote_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            vip = request.data.get('vip')
            lvName = request.data.get('lvName')
            data = {
                "command": "enableCopyLv",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "lvName": lvName,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/copyLv", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def enable_copy_lv(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中删除对应ping节点的脚本用于本机的健康检查"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    logger.error("The peer node is not connected!!!")
                    return get_error_result("PeerNodeNotConnected")
                else:
                    vip = request.data.get('vip')
                    vipNic = request.data.get('vipNic')
                    lvName = request.data.get('lvName')
                    # 判断：如果vip所在节点不是primary则不可以启用
                    if vip == "" or vipNic == "":
                        logger.error("The current node does not have VIP!!!")
                        return get_error_result("CurrentNodeNotHaveVip")
                    isOwnVip = check_ip_on_interface(vip, vipNic)
                    if not isOwnVip:
                        logger.error("The current node does not have VIP!!!")
                        return get_error_result("CurrentNodeNotHaveVip")
                    getRoleCmd = "drbdadm role %s" % lvName
                    (status, role) = run_cmd(getRoleCmd)
                    if status != 0:
                        if 'not defined in your config' in role:
                            logger.error("The replication logical volume resource does not exist!!!")
                            return get_error_result("CopyLvResourceNotExist")
                        elif 'Unknown resource' in role:
                            logger.error("The replication logical volume resource is not started!!!")
                            return get_error_result("CopyLvResourceNotStarted")
                        else:
                            logger.error("Failed to get replication logical volume resource role!!!")
                            return get_error_result("GetCopyLvResourceRoleError")
                    if role.lower() != "primary":
                        logger.error("The role of replication logical volume resource is not primary!!!")
                        return get_error_result("CopyLvResRoleNotPrimary")
                    # b、本地禁用ping node
                    resp = self.enable_local_copy_lv(request)
                    if resp.get('code') != 0:
                        logger.error("local host enable copy lv ha failed!!!")
                        return resp

                    # a、发起http请求对端机器copy lv ha
                    resp = self.enable_remote_copy_lv(request)
                    if resp.get('code') != 0:
                        logger.error("peer host enable copy lv ha failed!!!")
                        # 本地回滚
                        self.rollback_enable_local_copy_lv(request)
                        return resp
            else:
                resp = self.enable_local_copy_lv(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_disable_local_copy_lv(self, request):
        try:
            # 回滚文件数据
            if self.cacheData.get('configInfo'):
                config_info_to_file(self.cacheData['configInfo'])
            # 配置重载
            serviceStatus = get_service_status("keepalived")
            if serviceStatus and serviceStatus["status"] == "running":
                reload_service("keepalived")
        except Exception as err:
            logger.error(f"rollback_disable_local_copy_lv exception: {err}")
            logger.error(''.join(traceback.format_exc()))

    def disable_local_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            viNum = request.data.get('viNum')
            # 心跳所在网卡
            localHeartbeatNic = request.data.get('localHeartbeatNic')
            lvName = request.data.get('lvName')            
            # 1. 获取配置文件的信息
            configInfo = {
                "vrrp_instance": {},
                "vrrp_script": {},
                "global_defs": {}
            }
            configInfo = read_config_file_to_dict()
            # 备份文件数据，用于回滚
            self.cacheData['configInfo'] = configInfo

            # 2. 根据请求参数，添加ping node
            vrrpScriptName = "check_drbd_vi%s_%s" % (viNum, lvName)
            vrrpInstName = "vrrp_instance vi" + viNum
            updatedVrrpInst = configInfo['vrrp_instance'][vrrpInstName]
            # 兼容脱机操作导致的数据不对称情况
            if vrrpScriptName not in updatedVrrpInst["track_script"]:
                resp = get_error_result("Success")
                return resp
            updatedVrrpInst["track_script"].remove(vrrpScriptName)
            # 3. 新增VIP更新到变量中
            if "vrrp_instance" not in configInfo.keys():
                configInfo['vrrp_instance'] = {}            
            configInfo['vrrp_instance'].update({vrrpInstName: updatedVrrpInst})
            # 4. 更新配置文件
            config_info_to_file(configInfo)
            # 如果keepalived服务正常启动中，则重载keepalived服务的配置
            serviceStatus = get_service_status("keepalived")
            if serviceStatus != None:
                serviceStatus = serviceStatus["status"]
            if serviceStatus == "running":
                reloadOk = reload_service("keepalived")
                if not reloadOk:
                    logger.error("Failed to reload dual-control service!!!")
                    resp = get_error_result("ReloadDualControlServiceError")            
            return resp
        except Exception as e:
            logger.error("call disable_local_copy_lv error!!!")
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def disable_remote_copy_lv(self, request):
        try:
            resp = get_error_result("Success")
            remoteHeartbeatNic = request.data.get('remoteHeartbeatNic')
            viNum = request.data.get('viNum')
            vip = request.data.get('vip')
            lvName = request.data.get('lvName')
            data = {
                "command": "disableCopyLv",
                "requestEnd": "backend",
                "viNum": viNum,
                "vip": vip,
                "lvName": lvName,
                "localHeartbeatNic": remoteHeartbeatNic
            }
            return peer_post("/cluster/doubleCtlSetting/copyLv", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def disable_copy_lv(self, request, *args, **kwargs):
        """在keepalived.conf配置文件中禁用对应ping节点的脚本用于本机的健康检查"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                peerStatus = peerInfo["status"]
                remoteHost = peerInfo["host_name"]
                # 对端机器不正常，直接返回信息就是只有当前本机的
                if peerStatus == -1:
                    return self.disable_local_copy_lv(request)
                else:
                    # a、本地禁用ping node
                    resp = self.disable_local_copy_lv(request)
                    if resp.get('code') != 0:
                        logger.error("local host disable_local_copy_lv failed!!!")
                        return resp

                    # b、发起http请求对端机器添加ping node
                    resp = self.disable_remote_copy_lv(request)
                    if resp.get('code') != 0:
                        logger.error("peer host disable_local_copy_lv failed!!!")
                        # 本地回滚
                        self.rollback_disable_local_copy_lv(request)
                        return resp
            else:
                resp = self.disable_local_copy_lv(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp




CHECK_DRBD_FILE_CONTENT = '''#!/usr/bin/bash
#检测drbd资源各种状态是否正常，出现异常，则关闭keepalived，进行故障切换
# 关闭keepalived服务会导致当前机器所有其他的双机资源发生故障迁移
vip=$1
resource=$2
datetime=`date +"%Y-%m-%d"`
logFile=''' + DOUBLE_CONTROL_LOG_PATH + '''/check_drbd_$resource.log.${datetime}
echo "[`date +"%Y-%m-%d %H:%M:%S"`]starting check drbd $resource status from $vip......" >> $logFile
echo "vip: $vip" >> $logFile
echo "resource: $resource" >> $logFile
# 判断是否具有vip,没有vip情况，也即为keepalived的backup机器，所以无需监控双机资源
if [ `ip a show |grep $vip|wc -l` -ne 1 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] without vip: $vip exit 000000000000000000" >> $logFile
        exit 0
fi

# Resource Roles：drbdadm role <resource>，，必须是Primary
roleRes=`drbdadm role $resource` >> $logFile  2>&1
#判断上一步执行结果 等于0成功
if [ $? != 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource role faild: $roleRes from $vip ." >> $logFile
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] stop keepalived service" >> $logFile
        systemctl stop keepalived >> $logFile  2>&1
        exit 1
fi

# Disk States：drbdadm dstate <resource>，，不能是Failed
dstateRes=`drbdadm dstate $resource` >> $logFile  2>&1
#判断上一步执行结果 等于0成功
if [ $? != 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource dstatus faild: $dstateRes from $vip ." >> $logFile
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] stop keepalived service" >> $logFile
        systemctl stop keepalived >> $logFile  2>&1
        exit 1
fi

# Connection States： drbdadm cstate <resource>，，必须是Connected
cstateRes=`drbdadm cstate $resource` >> $logFile  2>&1
#判断上一步执行结果 等于0成功
if [ $? != 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource cstatus faild: $cstateRes from $vip ." >> $logFile
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] stop keepalived service" >> $logFile
        systemctl stop keepalived >> $logFile  2>&1
        exit 1
fi

# 如果包含vip运行，并且是Secondary的role，那直接强制故障切换为Primary脱机运行
if [ $roleRes = "Secondary" ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource role is Secondary from $vip ." >> $logFile
        # 执行drbd资源的切换为Primary脱机运行, to_master/<resource>.sh
        current_dir=$(dirname "$0")
        shellFile="${current_dir}/to_master/drbd_${resource}.sh"
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] start running $shellFile ..." >> $logFile
        bash "$shellFile"
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] end run $shellFile " >> $logFile
        exit 1
fi

# 正常双机运行
if [ $roleRes = "Primary" ] && [ $cstateRes = "Connected" ] && [[ $dstateRes != *"Failed"* ]] && [[ $dstateRes != *"Diskless"* ]]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource:正常双机运行 from $vip ." >> $logFile
        exit 0
# 正常脱机运行
elif [ $roleRes = "Primary" ] && [ $cstateRes = "StandAlone" ] && [[ $dstateRes != *"Failed"* ]] && [[ $dstateRes != *"Diskless"* ]]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource:正常脱机运行 from $vip ." >> $logFile
        exit 0
# 正常主机连接中运行, drbd盘应该是可以使用的
elif [ $roleRes = "Primary" ] && [ $cstateRes = "Connecting" ] && [[ $dstateRes != *"Failed"* ]] && [[ $dstateRes != *"Diskless"* ]]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource:正常主机Primary连接资源中... from $vip ." >> $logFile
        exit 0
# 其他情况则认为是异常drbd资源运行，也即出现故障，需要故障切换，直接关闭当前机器的keepalived服务
else
        downRes=`drbdadm disconnect --force $resource` >> $logFile  2>&1
        #判断上一步执行结果 等于0成功
        if [ $? != 0 ]; then
                echo "[`date +"%Y-%m-%d %H:%M:%S"`] drbdadm disconnect --force $resource failed" >> $logFile
        else
                echo "[`date +"%Y-%m-%d %H:%M:%S"`] drbdadm disconnect --force $resource success" >> $logFile
        fi
        echo "[`date +"%Y-%m-%d %H:%M:%S"`]end check drbd $resource : $roleRes $cstateRes $dstateRes from $vip ." >> $logFile
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] stop keepalived service" >> $logFile
        systemctl stop keepalived >> $logFile  2>&1
        exit 1
fi
'''

CHECK_GATEWAY_FILE_CONTENT = '''#!/usr/bin/bash

#检测$vip 能否ping通$gateway：
vip=$1
gateway=$2

datetime=`date +"%Y-%m-%d"`
logFile=''' + DOUBLE_CONTROL_LOG_PATH + '''/check_gateway_$gateway.log.${datetime}
echo "[`date +"%Y-%m-%d %H:%M:%S"`]starting ping gateway from ${vip}......" >> $logFile
echo "vip: $vip" >> $logFile
echo "gateway: $gateway" >> $logFile
# 判断是否具有vip,没有vip情况，也即为keepalived的backup机器，所以无需监控双机资源
if [ `ip a show |grep $vip|wc -l` -ne 1 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] end without vip: $vip, exit 000000000000000000" >> $logFile
        exit 0
fi

ping -I $vip  -W 1 -c 3 $gateway >> $logFile 2>&1
#判断上一步执行结果 等于0成功
if [ $? = 0 ]; then
        echo "exit 000000000000000000" >> $logFile
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] end ping gateway from $vip ." >> $logFile
        exit 0
else
        echo "exit 111111111111111111" >> $logFile
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] end ping gateway from $vip." >> $logFile
        systemctl stop keepalived >> $logFile 2>&1
        exit 1
fi
'''

TO_MASTER_FILE_CONTENT = '''#!/bin/bash

# 函数：检查文件是否包含给定字符串并执行 drbdadm role 命令
# 参数1：目录路径
# 参数2：目标字符串
function check_and_execute_drbdadm_role() {
    local drbdConfPath="$1"
    local target_string="$2"

    for drbdFilename in "$drbdConfPath"*.res; do
        if grep -q "device $target_string" "$drbdFilename"; then
            local resName=$(basename "$drbdFilename" .res)
            local result=$(drbdadm role "$resName")
            if [[ "$result" == *"Primary"* ]]; then
                return 0
            else
                echo "[`date +"%Y-%m-%d %H:%M:%S"`] exist $target_string drbd conf, but role is Secondary" >> $logFile
                return 1
            fi
        fi
    done
    echo "[`date +"%Y-%m-%d %H:%M:%S"`] not exist $target_string drbd conf" >> $logFile
    return 0
}

# 函数：检查backing-store并可能重命名文件
check_and_rename_files() {
    local conf_dir=$1

    # 遍历conf_dir目录下的文件
    for filename in "$conf_dir"/*; do
        # 提取文件名（不包括路径）和文件后缀
        local basename=$(basename -- "$filename")
        local extension="${basename##*.}"

        # 跳过非.conf和.invalid文件
        if [[ "$extension" != "conf" && "$extension" != "invalid" ]]; then
            continue
        fi

        # 读取文件内容
        local content=$(cat "$filename")

        # 使用awk提取所有的backing-store值
        # 假设backing-store后面紧跟的值没有空格或其他特殊字符
        local backing_stores=$(echo "$content" | awk '/backing-store/ {print $2}')

        # 检查每个设备是否存在
        local new_suffix=".conf"
        for device in $backing_stores; do
            if [[ ! -e "$device" ]]; then
                new_suffix=".invalid"
                break
            fi
            check_and_execute_drbdadm_role "$drbdConfPath" "$device"
            if [ $? -ne 0 ]; then
                echo "[`date +"%Y-%m-%d %H:%M:%S"`] check ${device} returned false" >> $logFile
                new_suffix=".invalid"
                break
            fi
        done

        # 获取旧后缀
        local old_suffix=".$extension"

        # 如果新后缀和旧后缀不同，则重命名文件
        if [[ "$new_suffix" != "$old_suffix" ]]; then
            local new_filename="${basename%.*}$new_suffix"
            local new_file_path="$conf_dir/$new_filename"
            mv "$filename" "$new_file_path"
            echo "[`date +"%Y-%m-%d %H:%M:%S"`] Renamed $filename to $new_file_path" >> $logFile
        fi
    done
}

process_nfs_config_file() {
    local nfs_conf_file=$1
    local temp_file=$(mktemp)  # 创建临时文件

    while IFS= read -r line; do
        line=$(echo "$line" | awk '{$1=$1};1')  # 去除行首尾的空白字符
        authInfo=$(echo "$line" | awk '{$1=""; print}')
        nfsPath=$(echo "$line" | awk '{print $1}')

        if [[ "$line" == "#/"* ]]; then
            nfsPath=$(echo "$line" | cut -d' ' -f1 | sed 's/^#//')
        fi

        # 根据目录是否存在，组新的配置行
        newLine="$nfsPath $authInfo"
        if [ ! -d "$nfsPath" ]; then
            newLine="#$nfsPath $authInfo"
        fi

        # 新行信息追加到临时文件
        echo "$newLine" >> "$temp_file"
    done < "$nfsConfFile"

    # 将临时文件写回原文件
    mv "$temp_file" "$nfs_conf_file"
}


vrrpInstName=$1
datetime=`date +"%Y-%m-%d"`
logFile=''' + DOUBLE_CONTROL_LOG_PATH + '''/to_master_${vrrpInstName}.log.${datetime}
dateTime=`date "+%Y-%m-%d %H:%M:%S"`
tgtd_conf_dir="/etc/tgt/conf.d"
drbdConfPath="/usr/local/etc/drbd.d/"
nfsConfFile="/etc/exports"

echo "[${dateTime}]: starting to_master handler..." >> $logFile

## 重启相关需要高可用的应用服务
# process nfs conf
process_nfs_config_file "$nfsConfFile"
systemctl restart nfs >> $logFile  2>&1
if [ $? == 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] success to restart nfs service" >> $logFile
else
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] faild to restart nfs service" >> $logFile
fi

systemctl restart smb >> $logFile  2>&1
if [ $? == 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] success to restart samba service" >> $logFile
else
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] faild to restart samba service" >> $logFile
fi

systemctl restart vsftpd >> $logFile  2>&1
if [ $? == 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] success to restart vsftpd service" >> $logFile
else
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] faild to restart vsftpd service" >> $logFile
fi

# check tgtd conf
check_and_rename_files "$tgtd_conf_dir"
ps -ef|grep -vE 'grep|vi'|grep tgtd|awk '{print $2}'|xargs kill -9
systemctl start tgtd >> $logFile  2>&1
if [ $? == 0 ]; then
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] success to restart tgtd service" >> $logFile
else
        echo "[`date +"%Y-%m-%d %H:%M:%S"`] faild to restart tgtd service" >> $logFile
fi
##echo "192.168.0.33 get the master on ${dateTime}, please handler question quickly!!!" | mail -s "keepalived alert" 769032297@qq.com
dateTime=`date "+%Y-%m-%d %H:%M:%S"`
echo "[${dateTime}]: end to_master handler." >> $logFile
'''

TO_BACKUP_FILE_CONTENT = '''#!/bin/bash
vrrpInstName=$1
datetime=`date +"%Y-%m-%d"`
logFile=''' + DOUBLE_CONTROL_LOG_PATH + '''/to_backup_${vrrpInstName}.log.${datetime}
dateTime=`date "+%Y-%m-%d %H:%M:%S"`
#echo "192.168.0.33 get the backup on ${dateTime}, please handler question quickly!!!" | mail -s "keepalived alert" 769032297@qq.com
echo "[${dateTime}]: starting to_backup handler..." >> $logFile
#umount /dev/drbd0
#drbdadm down lv1
#drbdadm up lv1
#drbdadm disconnect lv1
#drbdadm secondary lv1
#drbdadm --discard-my-data connect lv1
dateTime=`date "+%Y-%m-%d %H:%M:%S"`
echo "[${dateTime}]: end to_backup handler." >> $logFile
'''


def autoUpdateFailoverShells():
    '''
    脚本文件：
        check_drbd.sh
        check_gateway.sh
        to_master.sh
        to_backup.sh
    目录：to_master
    '''
    # 判断keepalived路径是否存在，不存在则报错
    if not os.path.exists(DOUBLE_CONTROL_CONFIG_PATH):
        logger.error(f'{DOUBLE_CONTROL_CONFIG_PATH} dirctory not exists!!!')
        return
    # 自动生成to_master目录，该目录用于记录每个drbd盘的故障迁移脚本的目录
    if not os.path.exists(DOUBLE_CONTROL_CONFIG_PATH + "/to_master"):
        os.mkdir(DOUBLE_CONTROL_CONFIG_PATH + "/to_master")
    # 自动生成脚本文件，并且添加执行权限
    failoverShels = {
        'check_drbd.sh': CHECK_DRBD_FILE_CONTENT,
        'check_gateway.sh': CHECK_GATEWAY_FILE_CONTENT,
        'to_master.sh': TO_MASTER_FILE_CONTENT,
        'to_backup.sh': TO_BACKUP_FILE_CONTENT
    }
    for fileName, fileContent in failoverShels.items():
        filePath = DOUBLE_CONTROL_CONFIG_PATH + "/" + fileName;
        with open(filePath, 'w', encoding='utf-8') as file:  
            file.write(fileContent)
            run_cmd(f'chmod +x {filePath}')

# 自动部署故障迁移脚本
autoUpdateFailoverShells()
