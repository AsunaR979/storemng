import subprocess
import traceback
import logging
import re
import os
import glob
import psutil
from enum import Enum
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from web_manage.cluster.drbd.async_update import CopyLvAsyncUpdate
from web_manage.cluster.drbd.models import CopyLvAsyncTask
from web_manage.cluster.keepalived.views import read_config_file_to_dict
from web_manage.common.constants import COPY_LV_CONFIG_PATH, COPY_LV_PORTS, TGTD_CONFIG_FILE_PATH
from web_manage.common.utils import JSONResponse, get_error_result, get_device_mountpoint, is_include_in_arr
from web_manage.common.cmdutils import run_cmd
from web_manage.common.log import insert_operation_log
from web_manage.cluster.models import *
from web_manage.common.http import peer_post
from web_manage.hardware.models import LvInfo
from web_manage.store.nas.models import NasDir

logger = logging.getLogger(__name__)



def drbd_file_to_dict(cfgFile):
    '''
    drbd的配置文件信息解析到字典中
    {
        "resName": "lv1",
        "protocol": "A/C", # A异步/C同步
        "node111": {
            'device': '/dev/drbd0',
            'disk': '/dev/vg1/lv1',
            'address': '192.168.0.12:8800',
            'node-id': '0',
        },
        "node222": {
            'device': '/dev/drbd0',
            'disk': '/dev/vg1/lv1',
            'address': '192.168.0.22:8800',
            'node-id': '1',
        }
    }
    '''
    try:
        # 定义最终反馈给前端的数据
        resp = {}
        # 定义正则表达式模式
        resource_pattern = re.compile(r'resource\s+(\w+)\s+{.*?protocol\s+(\w+);\s+on\s+([\w-]+)\s+\{.*?device\s+([\w/]+);\s+disk\s+([\w/]+);\s+address\s+([\d.]+:\d+);\s+node-id\s+([\w/]+);', re.DOTALL)

        # 读取文件内容
        if not os.path.exists(cfgFile):
            return resp
        with open(cfgFile, 'r') as file:
            content = file.read()

        # 解析资源名和协议
        match = resource_pattern.search(content)
        resp["resName"] = match.group(1)
        resp["protocol"] = match.group(2)

        # 解析节点信息
        node_pattern = re.compile(r'on\s+([\w-]+)\s+\{.*?device\s+([\w/]+);\s+disk\s+([\w/]+);\s+address\s+([\d.]+:\d+);\s+node-id\s+([\w/]+);', re.DOTALL)
        nodes = {}
        for match in node_pattern.finditer(content):
            nodeName = match.group(1)
            device = match.group(2)
            disk = match.group(3)
            
            address = match.group(4)
            nodeId = match.group(5)
            nodes[nodeName] = {
                'device': device,
                'disk': disk,
                'address': address,
                'node-id': nodeId,
            }
        resp.update(nodes)
        return resp
    except Exception as err:
        logger.error(f"parse drbd config file error: {err}")
        logger.error(''.join(traceback.format_exc()))

def dict_to_drbd_file(cfgDictInfo):
    '''
    字典数据，写入到drbd的配置文件中
    字典数据结构如下：
    {
        "resName": "lv1",
        "mode": "A/C", # A异步/C同步

        "localHostname": "node111",
        'localDevice': '/dev/drbd0',
        'localLvPath': '/dev/vg1/lv1',
        'localAddress': '192.168.0.12:8800',
        'localNodeId': '0',

        "remoteHostname": "node111",
        'remoteDevice': '/dev/drbd0',
        'remoteLvPath': '/dev/vg1/lv1',
        'remoteAddress': '192.168.0.12:8800',
        'remoteNodeId': '1',
    }
    '''
    try:
        # 组合drbd的资源配置信息
        resInfo = [
            "resource %s {" % cfgDictInfo['resName'],     
            "  protocol %s;" % cfgDictInfo['mode'],
            "  on %s {" % cfgDictInfo['localHostname'],
            "    device %s;" % cfgDictInfo['localDevice'],
            "    disk %s;" % cfgDictInfo['localLvPath'],
            "    address %s;" % cfgDictInfo['localAddress'],
            "    node-id %s;" % cfgDictInfo['localNodeId'],  # "0"/"1"
            "    meta-disk internal;",
            "  }",
            "  on %s {" % cfgDictInfo['remoteHostname'],
            "    device %s;" % cfgDictInfo['remoteDevice'],
            "    disk %s;" % cfgDictInfo['remoteLvPath'],
            "    address %s;" % cfgDictInfo['remoteAddress'],
            "    node-id %s;" % cfgDictInfo['remoteNodeId'], # local和remote不能相同
            "    meta-disk internal;",
            "  }",
            "}"
        ]
        # 通过换行符号拼接字符串
        resInfo = "\n".join(resInfo)
        # 资源配置信息写入文件中（注意一个drbd资源写一个单独配置文件）
        configDir = COPY_LV_CONFIG_PATH  # 配置需要放到storesys.settings文件中去
        cfgFileName = cfgDictInfo['resName'] + ".res"
        cfg = open(configDir + cfgFileName, "w")
        try:
            cfg.write(resInfo)
        finally:
            cfg.close()
        return True
    except Exception as err:
        logger.error(f"write drbd config file error: {err}")
        logger.error(''.join(traceback.format_exc()))
        return False

    
class LvCopyCmd(Enum):
    CreateLvCopy = "createLvCopy"
    GetLvCopyInfo = "getLvCopyInfo"
    GetAllLvCopyInfo = "getAllLvCopyInfo"
    UpdateLvCopy = "updateLvCopy"
    SartLvCopy = "startLvCopy"
    StopLvCopy = "stopLvCopy"
    DeleteLvCopy = "deleteLvCopy"
    AlterRoleLvCopy = "alterRoleLvCopy"
    MountLvCopy = "mountLvCopy"
    UmountLvCopy = "umountLvCopy"
    ForceToStandalone = "forceToStandalone"
    GetAllLvCopyMapperInfo = "getAllLvCopyMapperInfo"


class LvCopyView(APIView):
    """drbd 卷复制功能"""
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in LvCopyCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'role': openapi.Schema(type=openapi.TYPE_STRING),
            'port': openapi.Schema(type=openapi.TYPE_STRING),            
            'localLvPath': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteLvPath': openapi.Schema(type=openapi.TYPE_STRING),
            'localNic': openapi.Schema(type=openapi.TYPE_STRING),
            'localIp': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteNic': openapi.Schema(type=openapi.TYPE_STRING),
            'remoteIp': openapi.Schema(type=openapi.TYPE_STRING),
            'mode': openapi.Schema(type=openapi.TYPE_STRING),
            'rate': openapi.Schema(type=openapi.TYPE_STRING),
            "devicePath": openapi.Schema(type=openapi.TYPE_STRING),
            "mountDir": openapi.Schema(type=openapi.TYPE_STRING),
            "taskInfo": openapi.Schema(type=openapi.TYPE_OBJECT),
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
            if command not in ["getLvCopyInfo", "getAllLvCopyInfo", "getAllLvCopyMapperInfo"]:
                insert_operation_log(msg, ret["msg"], user_info)
            if command == "createLvCopy":
                ret = self.create_lv_copy(request, args, kwargs)
            elif command == "getLvCopyInfo":
                ret = self.get_lv_copy_info(request, args, kwargs)
            elif command == "getAllLvCopyInfo":
                ret = self.get_all_lv_copy_info(request, args, kwargs)
            elif command == "getAllLvCopyMapperInfo":
                ret = self.get_all_lv_copy_mapper_info(request, args, kwargs)                          
            elif command == "updateLvCopy":
                ret = self.update_lv_copy(request, args, kwargs)
            elif command == "stopLvCopy":
                ret = self.stop_lv_copy(request, args, kwargs)
            elif command == "startLvCopy":
                ret = self.start_lv_copy(request, args, kwargs)                
            elif command == "deleteLvCopy":
                ret = self.delete_lv_copy(request, args, kwargs)
            elif command == "alterRoleLvCopy":
                ret = self.alter_role_lv_copy(request, args, kwargs)
            elif command == "mountLvCopy":
                ret = self.mount_lv_copy(request, args, kwargs)                    
            elif command == "umountLvCopy":
                ret = self.umount_lv_copy(request, args, kwargs)
            elif command == "forceToStandalone":
                ret = self.force_to_standalone(request, args, kwargs)                   
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def is_double_control_resource(self, lvName):
        isDoubleCtlRes = False
        isEnabledDoubleCtlRes = False

        configInfo = read_config_file_to_dict()
        if configInfo is None or 'vrrp_script' not in configInfo.keys():
            return (isDoubleCtlRes, isEnabledDoubleCtlRes)
                
        if 'vrrp_instance' not in configInfo.keys():
            isEnabledDoubleCtlRes = False
        # 1. 判断drbd盘是否已经是双机资源
        drbdScriptNameMath = 'vrrp_script check_drbd_.*_%s' % (lvName)
        for str in configInfo['vrrp_script'].keys():
            if re.match(drbdScriptNameMath, str):
                isDoubleCtlRes = True
        # 2. 判断drbd盘是否已经是已启用高可用监控的双机资源
        if 'vrrp_instance' not in configInfo.keys():
            isEnabledDoubleCtlRes = False
        else:
            # 得到所有的track_script数组
            trackScript = []
            for elementKey in configInfo['vrrp_instance'].keys():
                vrrpInst = configInfo['vrrp_instance'][elementKey]
                trackScript.extend(vrrpInst['track_script'])
            # 心跳网卡是未知的
            drbdScriptNameMath = 'check_drbd_.*_%s' % (lvName)
            for str in trackScript:
                if re.match(drbdScriptNameMath, str):
                    isEnabledDoubleCtlRes = True
        
        return (isDoubleCtlRes, isEnabledDoubleCtlRes)

    def get_new_drbd_num(self):
        try:
            drbdNums = []
            for file_path in glob.glob(os.path.join(COPY_LV_CONFIG_PATH, "*.res")):
                if os.path.isdir(file_path ):
                    continue
                with open(file_path , 'r') as file:  
                    content = file.read()
                    matchs = re.findall(r"device /dev/drbd(\d+)", content)
                    if matchs:
                        drbdNums.append(int(matchs[0]))
            if drbdNums:
                return max(drbdNums) + 1
            else:
                return 0
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))

    def get_new_drbd_port(self):
        try:
            startPort = COPY_LV_PORTS.split(',')[0]
            endPort = COPY_LV_PORTS.split(',')[1]
            portList = range(int(startPort), int(endPort))
            # 过滤掉已经使用过的port
            usedPorts = []
            port_set = set()  # 用集合来存储端口号，以去重
            port_pattern = re.compile(r"address\s+(\d+\.\d+\.\d+\.\d+):(\d+);")
            for filename in os.listdir(COPY_LV_CONFIG_PATH):
                if filename.endswith(".res"):
                    filepath = os.path.join(COPY_LV_CONFIG_PATH, filename)
                    with open(filepath, "r") as file:
                        content = file.read()
                        matches = port_pattern.findall(content)
                        for _, port in matches:
                            port_set.add(int(port))  # 将端口号转换为整数并添加到集合中

            usedPorts = list(port_set)  # 将集合转换为列表
            usedPorts.sort()  # 按升序排序

            newPort = min([port for port in portList if port not in usedPorts])
            return newPort
            


            
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))

    def create_local_lv_copy(self, request, port):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            role = request.data.get('role')
            localLvPath = request.data.get('localLvPath')
            remoteLvPath = request.data.get('remoteLvPath')
            localIp = request.data.get('localIp')
            remoteIp = request.data.get('remoteIp')
            mode = request.data.get('mode')  # 异步 ”A“， 同步 ”C"
            wipeLv = request.data.get('wipeLv')
            # rate = request.data.get('rate')  暂时不处理
            taskInfo = request.data.get('taskInfo')
            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]

            # 判断逻辑卷是否已用作san
            backing_stores = []
            for filename in os.listdir(TGTD_CONFIG_FILE_PATH):
                if not filename.endswith(('.conf', '.invalid','.inactive')):
                    continue
                file_path = os.path.join(TGTD_CONFIG_FILE_PATH, filename)
                with open(file_path, 'r') as f:
                    content = f.read()
                # 使用正则表达式提取所有的backing-store值
                backing_stores.extend([line.split(' ')[1].strip() for line in content.split('\n') if 'backing-store' in line])
            for stores in backing_stores:
                if localLvPath in stores:
                    logger.error("The san service is in use. Procedure")
                    ret = get_error_result("CantUmountUsedLv")
                    return ret
            #判断逻辑卷是否用于nas
            exists = NasDir.objects.filter(dev_path=localLvPath).exists()
            if exists:
                logger.error("The nas service is in use. Procedure")
                ret = get_error_result("CantUmountUsedLv")
                return ret

            # 获取当前节点hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            # 获取对端节点hostname，从数据库中获取
            if ClusterNode.objects.count() > 0:
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
            else:
                peerInfo = {"ip": "", "host_name": "", "status": -1}
            remoteHostname = peerInfo["host_name"]
            # 获取网卡编号，例如ens33,则得到33, eth0,则得到0,这个数字用于drbd的虚拟磁盘命名，可以保证唯一性
            # 设置虚拟drbd磁盘路径
            drbdNum = self.get_new_drbd_num()
            localDevice = "/dev/drbd%s" % drbdNum
            remoteDevice = "/dev/drbd%s" % drbdNum
            # 获取资源监控地址，后端传过来的port直接使用，不用重新生成
            if requestEnd == "backend":
                port = request.data.get('port')
            localAddress = localIp  + ":" + str(port)
            remoteAddress = remoteIp + ":" + str(port)
                
            # 组合drbd的资源配置信息
            resInfo = [
                "resource %s {" % resName,     
                "  protocol %s;" % mode,
                "  on %s {" % localHostname,
                "    device %s;" % localDevice,
                "    disk %s;" % localLvPath,
                "    address %s;" % localAddress,
                "    node-id %s;" % ("0" if requestEnd == "frontend" else "1"),
                "    meta-disk internal;",
                "  }",
                "  on %s {" % remoteHostname,
                "    device %s;" % remoteDevice,
                "    disk %s;" % remoteLvPath,
                "    address %s;" % remoteAddress,
                "    node-id %s;" % ("1" if requestEnd == "frontend" else "0"),                
                "    meta-disk internal;",
                "  }",
                "}"
            ]
            # 通过换行符号拼接字符串
            resInfo = "\n".join(resInfo)
            # 资源配置信息写入文件中（注意一个drbd资源写一个单独配置文件）
            configDir = COPY_LV_CONFIG_PATH  # 配置需要放到storesys.settings文件中去
            cfgFileName = resName + ".res"
            cfg = open(configDir + cfgFileName, "w")
            try:
                cfg.write(resInfo)
            finally:
                cfg.close()

            # 判断是否需要擦除逻辑卷数据
            if wipeLv is True:
                wipeLvCmd = "wipefs -a %s" % (localLvPath)
                (status, wipeLvCmdOutput) = run_cmd(wipeLvCmd)
                if status != 0:
                    logger.error("Failed to wipe logical volume data!!!")
                    resp = get_error_result("WipeLvDataError")
                    return resp

            # 创建资源元数据
            createMdCmd = "drbdadm create-md --force %s" % (resName)
            (status, createMdCmdOutput) = run_cmd(createMdCmd)
            if status != 0:
                # 执行资源创建的回滚操作：删除已经创建的资源文件
                os.remove(configDir + cfgFileName)
                logger.error("Failed to create replication logical volume resource metadata!!!")
                # 已有文件系统的逻辑卷，无法创建元数据的报错
                if status == 40 and 'filesystem' in createMdCmdOutput:
                    resp = get_error_result("LvFoundFilesystemCantCreateMd")
                else:
                    resp = get_error_result("CreateCopyLvResMdError")
                return resp
            
            # 启用资源
            startMdCmd = "drbdadm up %s" % (resName)
            (status, startMdCmdOutput) = run_cmd(startMdCmd)
            if status != 0:
                # 执行资源创建的回滚操作
                logger.error("Failed to enable replication logical volume resource!!!")
                resp = get_error_result("StartCopyLvResError")
                return resp
            # 设置角色
            setRoleCmd = "drbdadm %s --force %s" % (role, resName)
            (status, setRoleCmdOutput) = run_cmd(setRoleCmd)
            if status != 0:
                logger.error("Failed to set role for replication logical volume resource!!!")
                resp = get_error_result("SetCopyLvResRoleError")
                return resp
            
            # 如果是异步模式，则需要添加异步同步数据策略
            if mode == "A":
                # 异步模式，强制脱机运行，只有在设定时间进行数据同步
                cmd = 'drbdadm disconnect {}'.format(resName)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    logger.error(f"{cmd} {output}!!!")
                    resp = get_error_result("ForceCopyLvToStandaloneFailed")
                    return resp
                if role.lower() == "primary":
                    CopyLvAsyncUpdate().add_async_update_data_job(resName, taskInfo)
            return resp
        except Exception as err:
            # 执行资源创建的回滚操作
            self.wipe_local_lv_copy(resName)
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def create_remote_lv_copy(self, request, port):
        try:
            localLvPath = request.data.get('localLvPath')
            remoteLvPath = request.data.get('remoteLvPath')
            localNic = request.data.get('localNic')
            localIp = request.data.get('localIp')
            remoteNic = request.data.get('remoteNic')
            remoteIp = request.data.get('remoteIp')
            mode = request.data.get('mode')  # 异步 ”A“， 同步 ”C"
            wipeLv = request.data.get('wipeLv')
            # rate = request.data.get('rate')  暂时不处理
            taskInfo = request.data.get('taskInfo')
            role = request.data.get('role')

            if role == 'primary':
                remoteRole = 'secondary'
            else:
                remoteRole = 'primary'

            data = {
                "command": "createLvCopy",
                "requestEnd": "backend",
                "role": remoteRole,
                "port": port,
                "localLvPath": remoteLvPath,
                "remoteLvPath": localLvPath,
                "localNic": remoteNic,
                "localIp": remoteIp,
                "remoteNic": localNic,
                "remoteIp": localIp,
                "mode": mode,
                "wipeLv": wipeLv,
                "taskInfo": taskInfo
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp            

    def wipe_local_lv_copy(self, resName):
        try:
            # 关闭资源
            stopMdCmd = "drbdadm down %s" % (resName)
            (status, stopMdCmdOutput) = run_cmd(stopMdCmd)
            if status != 0:
                logger.error("run: %s error!!!" %  stopMdCmd)
            
            # 删除资源元数据
            createMdCmd = "drbdadm wipe-md --force %s" % (resName)
            (status, createMdCmdOutput) = run_cmd(createMdCmd)
            if status != 0:
                logger.error("run: %s error!!!" %  createMdCmd)

            # 删除配置文件
            configDir = COPY_LV_CONFIG_PATH  # 配置需要放到storesys.settings文件中去
            cfgFileName = resName + ".res"
            os.remove(configDir + cfgFileName)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
        
    def create_lv_copy(self, request, *args, **kwargs):
        """创建卷复制：添加资源文件/usr/local/etc/drbd.d/路径下，文件名是 逻辑卷.res"""
        try:
            resp = get_error_result("Success")
            role = request.data.get('role')
            requestEnd = request.data.get('requestEnd')
            localLvPath = request.data.get('localLvPath')
            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]
            # 获取一个新的复制逻辑卷端口
            port = self.get_new_drbd_port()

            # 判断是否为前端发起请求：前端发起请求需要处理双机流程
            if requestEnd == "frontend":
                # 判断设置role：先处理role为secondary的机器
                if role == "primary":
                    # a、发起http请求对端机器创建并且启动资源
                    resp = self.create_remote_lv_copy(request, port)
                    if resp.get('code') != 0:
                        logger.error("peer host create drbd resource failed!!!")
                        return resp
                    # b、本地创建资源并且启动
                    resp = self.create_local_lv_copy(request, port)
                    if resp.get('code') != 0:
                        # 本地失败，发起对端进行回滚
                        logger.error("local failed, peer host rollback create drbd resource !!!")
                        self.delete_remote_lv_copy(request)
                        return resp
                else:
                    # a、本地创建资源并且启动（seconadary）
                    resp = self.create_local_lv_copy(request, port)
                    if resp.get('code') != 0:
                        logger.error("call create_local_lv_copy error!!!")
                        return resp
                    # b、发起http请求对端机器创建并且启动资源(primary)
                    resp = self.create_remote_lv_copy(request, port)
                    if resp.get('code') != 0:
                        logger.error("peer host create drbd primary resource failed!!!")
                        # 执行资源创建的回滚操作
                        self.wipe_local_lv_copy(resName)
                        return resp
            else:
                resp = self.create_local_lv_copy(request, port)
            return resp
        except Exception as err:
            # 执行资源创建的回滚操作
            self.wipe_local_lv_copy(resName)
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_lv_copy_info(self, request, *args, **kwargs):
        """获取卷复制信息"""
        try:
            localLvPath = request.data.get('localLvPath')
            # 定义最终反馈给前端的数据
            resp = {}
            # 获取当前节点hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            resp["localHostname"] = localHostname
            # 获取对端节点hostname，从数据库中获取
            if ClusterNode.objects.count():
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
            else:
                peerInfo = {"ip": "", "host_name": "", "status": -1}
            remoteHostname = peerInfo["host_name"]
            resp["remoteHostname"] = remoteHostname
            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]
            
            # 获取lv的资源文件
            resCfgFile = os.path.join(COPY_LV_CONFIG_PATH, resName + '.res')
            resp.update(self.get_lv_copy_file_info(resCfgFile))

            # 如果是异步模式：返回异步策略信息
            if resp["protocol"] == "A":
                task = CopyLvAsyncTask.objects.filter(resname=resp["resName"]).first()
                if task:
                    resp['taskInfo'] = {
                        "period": task.period,
                        "day": task.day,
                        "day_of_week": task.day_of_week,
                        "hour": task.hour,
                        "minute": task.minute,
                        "timeoutHours": task.timeout_hours
                    }
            # 输出结果
            resp = get_error_result("Success", resp)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_drbd_sync_status(self, resource_name):
        try:
            (status, dstate) = subprocess.getstatusoutput("drbdadm dstate %s" % resource_name)
            if status == 0 and dstate == "UpToDate/UpToDate":
                return "已同步"
            (status, output) = subprocess.getstatusoutput("drbdadm status %s" % resource_name)
            if status == 0:
                # 搜索同步进度  
                progress_match = re.search(r'replication:.* done:(\d+\.\d+)', output)  
                if progress_match:  
                    # 找到了同步进度，返回同步中及百分比  
                    progress = progress_match.group(1)  
                    return f"同步中（{progress}%）"
            return f"待同步"
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            return f"待同步"
    
    def get_lv_copy_file_info(self, cfgFile):
        try:
            # 定义最终反馈给前端的数据
            resp = {}
            # 定义正则表达式模式
            resource_pattern = re.compile(r'resource\s+(\w+)\s+{.*?protocol\s+(\w+);\s+on\s+([\w-]+)\s+\{.*?device\s+([\w/]+);\s+disk\s+([\w/]+);\s+address\s+([\d.]+:\d+);\s+node-id\s+([\w/]+);', re.DOTALL)

            # 读取文件内容
            if not os.path.exists(cfgFile):
                return resp
            with open(cfgFile, 'r') as file:
                content = file.read()

            resName = os.path.basename(cfgFile).split(".")[0]
            # 解析资源名和协议
            match = resource_pattern.search(content)
            resp["resName"] = match.group(1)
            resp["protocol"] = match.group(2)

            # 获取role信息
            (status, roleName) = subprocess.getstatusoutput("drbdadm role %s" % resName)
            resp["role"] = roleName
            if status != 0:
                resp["role"] = ""
            
            # 获取cstate资源主备连接状态信息
            (status, cstate) = subprocess.getstatusoutput("drbdadm cstate %s" % resName)
            resp["cstate"] = cstate
            if status != 0:
                resp["cstate"] = ""
            
            # 获取dstate资源磁盘状态信息
            resp["dstate"] = self.get_drbd_sync_status(resName)

            # 判断是否为双机资源
            (resp["isDoubleCtlRes"], resp["isEnabledDoubleCtlRes"]) = self.is_double_control_resource(resName)

            # 解析节点信息
            node_pattern = re.compile(r'on\s+([\w-]+)\s+\{.*?device\s+([\w/]+);\s+disk\s+([\w/]+);\s+address\s+([\d.]+:\d+);\s+node-id\s+([\w/]+);', re.DOTALL)
            nodes = {}
            for match in node_pattern.finditer(content):
                nodeName = match.group(1)
                device = match.group(2)
                disk = match.group(3)
                # 获取逻辑卷的存储类型，从数据库中获取
                vgName = disk.split('/')[2]
                lvInfo = LvInfo.objects.get(lvname=resName, vgname=vgName)
                storeType = lvInfo.store_type if LvInfo else ''
                
                address = match.group(4)
                nodeId = match.group(5)
                # 获取挂载目录和文件系统格式
                (fstype, mountpoint) = self.get_mount_info(device)
                nodes[nodeName] = {
                    'device': device,
                    'disk': disk,
                    'address': address,
                    'node-id': nodeId,
                    'fstype': fstype,
                    'mountpoint': mountpoint,
                    'store_type': storeType
                }
            resp.update(nodes)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            return None

    def get_mount_info(self, device):
        fstype = ""
        mountpoint = ""
        # 获取drbd虚拟盘的文件系统类型 
        checkFsCmd = "blkid %s" % device
        (status, fstype) = subprocess.getstatusoutput(checkFsCmd)
        if status == 0:
            match = re.search(r' TYPE=\"(.*?)\"', fstype)
            if match:
                fstype = match.group(1)
            match = re.search(r'PTTYPE=\"(.*?)\"', fstype)
            if match:
                fstype = match.group(1)
        else:
            fstype = ""

        # 获取所有磁盘分区信息
        partitions = psutil.disk_partitions()
        # 查找设备 device=/dev/drbd1 的信息
        for partition in partitions:
            if partition.device == device:
                mountpoint = partition.mountpoint
                break
        return (fstype, mountpoint)

    def get_all_lv_copy_info(self, request, *args, **kwargs):
        """获取卷复制信息"""
        try:
            # 定义最终反馈给前端的数据
            resp = {}
            # 获取当前节点hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            resp["localHostname"] = localHostname
            # 获取对端节点hostname，从数据库中获取
            if ClusterNode.objects.count():
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
            else:
                peerInfo = {"ip": "", "host_name": "", "status": -1}
            resp["remoteHostname"] = peerInfo["host_name"]
            resp["resourceArray"] = []
            # 获取lv的资源文件
            for resCfgFile in glob.glob(os.path.join(COPY_LV_CONFIG_PATH, '*.res')):
                resp["resourceArray"].append(self.get_lv_copy_file_info(resCfgFile))
            # 输出结果
            resp = get_error_result("Success", resp)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_all_lv_copy_mapper_info(self, request, *args, **kwargs):
        """获取卷复制和普通逻辑卷的映射关系字典信息"""
        try:
            # 创建一个空字典来存储device和disk信息
            device_disk_dict = {}
            # 遍历目录下的所有.res文件
            for filename in glob.glob(os.path.join(COPY_LV_CONFIG_PATH, '*.res')):
                with open(filename, 'r') as file:
                    # 读取文件内容
                    content = file.read()
                    # 使用正则表达式匹配device和disk信息
                    matches = re.findall(r'device\s+([\w/]+);\n\s+disk\s+([\w/]+);', content)
                    # 遍历匹配到的每一组device和disk信息
                    for device, disk in matches:
                        # 检查device是否已经在字典中
                        if device not in device_disk_dict:
                            # 如果不在，则添加到字典中
                            device_disk_dict[device] = disk
            # 输出结果
            resp = get_error_result("Success", device_disk_dict)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def rollback_update_local_lv_copy(self, request):
        try:
            localLvPath = request.data.get('localLvPath')

            resName = localLvPath.split("/")[-1]
            cfgFileName = resName + ".res"
            # 回滚文件数据
            with open(COPY_LV_CONFIG_PATH + cfgFileName, "w") as cfg:
                cfg.write(self.cacheData[cfgFileName])            
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
                        
    def update_local_lv_copy(self, request):
        try:
            resp = get_error_result("Success")
            port = request.data.get('port')
            localLvPath = request.data.get('localLvPath')
            remoteLvPath = request.data.get('remoteLvPath')
            localIp = request.data.get('localIp')
            remoteIp = request.data.get('remoteIp')
            mode = request.data.get('mode')  # 异步 ”A“， 同步 ”C"
            # rate = request.data.get('rate')  暂时不处理
            taskInfo = request.data.get('taskInfo') 

            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]
            # 获取当前节点hostname
            (status, localHostname) = run_cmd("hostname")
            if status != 0:
                logger.error("Failed to get the hostname!!!")
                resp = get_error_result("GetHostnameError")
                return resp
            # 获取对端节点hostname，从数据库中获取
            if ClusterNode.objects.count():
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
            else:
                peerInfo = {"ip": "", "host_name": "", "status": -1}
            remoteHostname = peerInfo["host_name"]
            # 获取lv的资源文件
            configDir = COPY_LV_CONFIG_PATH
            resCfgFile = os.path.join(configDir, resName + '.res')
            oldResInfo = self.get_lv_copy_file_info(resCfgFile)
            # 获取原始虚拟drbd磁盘路径
            localDevice = oldResInfo[localHostname]['device']
            remoteDevice = oldResInfo[remoteHostname]['device']       
            # 获取原始node-id节点编号
            localNodeId = oldResInfo[localHostname]['node-id']
            remoteNodeId = oldResInfo[remoteHostname]['node-id'] 
            # 获取资源监控地址
            localAddress = localIp  + ":" + port
            remoteAddress = remoteIp + ":" + port
            # 组合drbd的资源配置信息
            resInfo = [
                "resource %s {" % resName,     
                "  protocol %s;" % mode,
                "  on %s {" % localHostname,
                "    device %s;" % localDevice,
                "    disk %s;" % localLvPath,
                "    address %s;" % localAddress,
                "    node-id %s;" % localNodeId,
                "    meta-disk internal;",
                "  }",
                "  on %s {" % remoteHostname,
                "    device %s;" % remoteDevice,
                "    disk %s;" % remoteLvPath,
                "    address %s;" % remoteAddress,
                "    node-id %s;" % remoteNodeId,
                "    meta-disk internal;",
                "  }",
                "}"
            ]
            # 通过换行符号拼接字符串
            resInfo = "\n".join(resInfo)
            # 资源配置信息写入文件中（注意一个drbd资源写一个单独配置文件）
            cfgFileName = resName + ".res"
            # 先备份文件内容，用于回滚
            with open(COPY_LV_CONFIG_PATH + cfgFileName, "r") as cfg:
                self.cacheData[cfgFileName] = cfg.read()
            with open(COPY_LV_CONFIG_PATH + cfgFileName, "w") as cfg:
                cfg.write(resInfo)

            # 执行资源配置信息调整指令
            adjustCmd = "drbdadm -c %s adjust all" % (COPY_LV_CONFIG_PATH + cfgFileName)
            (status, adjustCmdOutput) = run_cmd(adjustCmd)
            if status != 0:
                logger.error("Failed to adjust replication logical volume resource!!!")
                resp = get_error_result("AdjustCopyLvResError")
                return resp
            
            # 如果是旧模式是异步，先删除异步策略
            if oldResInfo['protocol'] == "A":
                CopyLvAsyncUpdate().remove_async_update_data_job(resName)
            # 如果新模式是异步，则新建异步模式
            if mode == "A" and oldResInfo['role'].lower() == "primary":
                CopyLvAsyncUpdate().add_async_update_data_job(resName, taskInfo)            
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def update_remote_lv_copy(self, request):
        try:
            role = request.data.get('role')
            port = request.data.get('port')
            localLvPath = request.data.get('localLvPath')
            remoteLvPath = request.data.get('remoteLvPath')
            localNic = request.data.get('localNic')
            localIp = request.data.get('localIp')
            remoteNic = request.data.get('remoteNic')
            remoteIp = request.data.get('remoteIp')
            mode = request.data.get('mode')  # 异步 ”A“， 同步 ”C"
            # rate = request.data.get('rate')  暂时不处理
            taskInfo = request.data.get('taskInfo')

            data = {
                "command": "updateLvCopy",
                "requestEnd": "backend",
                "role": "primary" if role == "secondary" else "secondary",
                "port": port,
                "localLvPath": remoteLvPath,
                "remoteLvPath": localLvPath,
                "localNic": remoteNic,
                "localIp": remoteIp,
                "remoteNic": localNic,
                "remoteIp": localIp,
                "mode": mode,
                "taskInfo": taskInfo
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)

        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def update_lv_copy(self, request, *args, **kwargs):
        """更新卷复制：把之前的资源文件重新写入即可"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            localLvPath = request.data.get('localLvPath')
            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]

            # 判断是否为双机资源，如果已经是启用的双机资源，则不可以操作
            if self.is_double_control_resource(resName)[1]:
                logger.error("The enabled dual-machine resource, operation prohibited!!!")
                return get_error_result("DualMachineResIsEnabled")

            # 1.判断前后是否为前端发起：前端发起还需要处理对端机器
            if requestEnd == "frontend":
                # 判断如果drbd的资源是处于连接状态下，才会进行双机操作
                (status, cstate) = run_cmd("drbdadm cstate %s" % resName)
                if status != 0:
                    if 'not defined in your config' in cstate:
                        logger.error("The replication logical volume resource does not exist!!!")
                        resp = get_error_result("CopyLvResourceNotExist")
                        return resp
                    elif 'Unknown resource' in cstate:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to get the connection status of the replication logical volume!!!")
                        resp = get_error_result("GetCopyLvCstateError")
                        return resp
                # a、先发起对端执行更新
                resp = self.update_local_lv_copy(request)
                if resp.get('code') != 0:
                    logger.error("local host update drbd confige failed!!!")
                    return resp

                # b、连接正常才会处理对端机器，否则就是处理本地，把“脱机”情况包含进来了
                if cstate.lower() == "connected":
                    resp = self.update_remote_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("peer host update drbd confige failed!!!")
                        # 开启回滚本地更新
                        self.rollback_update_local_lv_copy(request)
                        return resp
            else:
                # 更新本地配置
                resp = self.update_local_lv_copy(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_stop_local_lv_copy(self, request):
        try:
            resName = request.data.get('lvName')
            if not resName:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]

            # 开启资源
            run_cmd(f"drbdadm up {resName}")
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def stop_local_lv_copy(self, request):
        """禁用本地卷复制功能"""
        try:
            resp = get_error_result("Success")
            resName = request.data.get('lvName')
            if not resName:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1] 

            # 关闭资源
            stopMdCmd = "drbdadm down %s" % (resName)
            (status, stopMdCmdOutput) = run_cmd(stopMdCmd)
            if status != 0:
                if 'opened by mount' in stopMdCmdOutput:
                    logger.error("The replication logical volume is already mounted, please unmount it first!!!")
                    resp = get_error_result("CopyLvAlreadyMounted")
                    return resp
                elif 'Device is held open' in stopMdCmdOutput:
                    logger.error("Device is held open by someone additional info from kernel!!!")
                    resp = get_error_result("CopyLvIsBusy")
                    return resp
                else:
                    logger.error("Failed to deactivate the replication logical volume resource!!!")
                    resp = get_error_result("StopCopyLvResError")
                    return resp
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def stop_remote_lv_copy(self, request):
        try:
            remoteLvPath = request.data.get('remoteLvPath')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]            
            data = {
                "command": "stopLvCopy",
                "requestEnd": "backend",
                "localLvPath": remoteLvPath,
                "lvName": resName
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def stop_lv_copy(self, request, *args, **kwargs):
        """禁用卷复制功能"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]

            # 判断是否为双机资源，如果已经是启用的双机资源，则不可以操作
            if self.is_double_control_resource(resName)[1]:
                logger.error("The enabled dual-machine resource, operation prohibited!!!")
                return get_error_result("DualMachineResIsEnabled")
            
            # 1.判断前后是否为前端发起：前端发起还需要处理对端机器
            if requestEnd == "frontend":
                # 判断如果drbd的资源是处于连接状态下，才会进行双机操作
                (status, cstate) = run_cmd("drbdadm cstate %s" % resName)
                if status != 0:
                    if 'not defined in your config' in cstate:
                        logger.error("The replication logical volume resource does not exist!!!")
                        resp = get_error_result("CopyLvResourceNotExist")
                        return resp
                    elif 'Unknown resource' in cstate:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to get the connection status of the replication logical volume!!!")
                        resp = get_error_result("GetCopyLvCstateError")
                        return resp
                # a、更新本地
                resp = self.stop_local_lv_copy(request)     
                if resp.get('code') != 0:
                    logger.error("local host stop drbd resource failed!!!")
                    return resp  
                # b、发起对端
                # 连接正常才会处理对端机器，否则就是处理本地，把“脱机”情况包含进来了
                if cstate.lower() == "connected":
                    resp = self.stop_remote_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("peer host stop drbd resource failed!!!")
                        # 回滚本地
                        self.rollback_stop_local_lv_copy(request)
                        return resp
            else:
                # 处理本地逻辑
                resp = self.stop_local_lv_copy(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def start_lv_copy(self, request, *args, **kwargs):
        """（单机功能：防止需要单击运行）根据不同角色启用卷复制功能"""
        try:
            resp = get_error_result("Success")
            role = request.data.get('role')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]

            # 判断是否为双机资源，如果已经是启用的双机资源，则不可以操作
            if self.is_double_control_resource(resName)[1]:
                logger.error("The enabled dual-machine resource, operation prohibited!!!")
                return get_error_result("DualMachineResIsEnabled")
            
            # 1.判断是否有挂载drbd虚拟盘,有的话先卸载才可以进入后续操作（用户界面操作卸载）
            # 2.关闭资源
            stopMdCmd = "drbdadm down %s" % (resName)
            (status, stopMdCmdOutput) = run_cmd(stopMdCmd)
            if status != 0:
                if 'opened by mount' in stopMdCmdOutput:
                    logger.error("The replication logical volume is already mounted, please unmount it first!!!")
                    resp = get_error_result("CopyLvAlreadyMounted")
                    return resp
                else:
                    logger.error("Failed to deactivate the replication logical volume resource!!!")
                    resp = get_error_result("StopCopyLvResError")
                    return resp
            # 3.启用资源
            startMdCmd = "drbdadm up %s" % (resName)
            (status, startMdCmdOutput) = run_cmd(startMdCmd)
            if status != 0:
                logger.error("Failed to enable replication logical volume resource!!!")
                resp = get_error_result("StartCopyLvResError")
                return resp

            # 4.设置角色
            if role == "primary":
                setRoleCmd = "drbdadm %s --force %s" % (role, resName)
                (status, setRoleCmdOutput) = run_cmd(setRoleCmd)
                if status != 0:
                    logger.error("Failed to set role for replication logical volume resource!!!")
                    resp = get_error_result("SetCopyLvResRoleError")
                    return resp
            else:
                getCstateCmd = "drbdadm cstate %s" % (resName)
                (status, cstate) = run_cmd(getCstateCmd)
                if status != 0:
                    if 'not defined in your config' in cstate:
                        logger.error("The replication logical volume resource does not exist!!!")
                        resp = get_error_result("CopyLvResourceNotExist")
                        return resp
                    elif 'Unknown resource' in cstate:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to get the connection status of the replication logical volume!!!")
                        resp = get_error_result("GetCopyLvCstateError")
                        return resp
                # if cstate.lower() != "connected":
                #     # 先关闭连接
                # 先断开默认连接
                disconnCmd = "drbdadm disconnect %s" % (resName)
                (status, disconnCmdOutput) = run_cmd(disconnCmd)
                if status != 0:
                    if 'Unknown resource' in disconnCmdOutput:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to disconnect the replication logical volume resource!!!")
                        resp = get_error_result("CopyLvDisconnectError")
                        return resp               
                # secondary角色直接放弃本地数据，连接对端即可
                connectCmd = "drbdadm --discard-my-data connect %s" % (resName)
                (status, connectCmdOutput) = run_cmd(connectCmd)
                if status != 0:
                    if 'Unknown resource' in connectCmdOutput:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to connect the replication logical volume resource!!!")
                        resp = get_error_result("CopyLvConnectError")
                        return resp

            # 如果设置为primay，则可以挂载使用，最后是否要挂载使用，由客户在逻辑卷界面去设置挂载
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp    

    def rollback_delete_local_lv_copy(self, request):
        try:
            localLvPath = request.data.get('localLvPath')
            resName = localLvPath.split("/")[-1]

            cfgFileName = resName + ".res"
            # 回滚配置文件
            with open(COPY_LV_CONFIG_PATH + cfgFileName, 'w') as f:
                f.write(self.cacheData[cfgFileName])
            # 创建资源
            run_cmd(f"drbdadm wipe-md --force {resName}")
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def delete_local_lv_copy(self, request):
        """删除本地卷复制"""
        try:
            resp = get_error_result("Success")
            localLvPath = request.data.get('localLvPath')
            # rate = request.data.get('rate')  暂时不处理
            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]

            # 关闭资源
            stopMdCmd = "drbdadm down %s" % (resName)
            (status, stopMdCmdOutput) = run_cmd(stopMdCmd)
            if status != 0:
                if 'opened by mount' in stopMdCmdOutput:
                    logger.error("The replication logical volume is already mounted, please unmount it first!!!")
                    resp = get_error_result("CopyLvAlreadyMounted")
                    return resp
                else:
                    logger.error("Failed to deactivate the replication logical volume resource!!!")
                    resp = get_error_result("StopCopyLvResError")
                    return resp
            
            # 删除资源元数据
            wipeMdCmd = "drbdadm wipe-md --force %s" % (resName)
            (status, wipeMdCmdOutput) = run_cmd(wipeMdCmd)
            if status != 0:
                if 'is configured' in wipeMdCmdOutput:
                    logger.error("The replication logical volume resource is enabled, please deactivate it first!!!")
                    resp = get_error_result("CopyLvResAlreadyStarted")
                    return resp
                else:
                    logger.error("Failed to wipe replication logical volume resource metadata!!!")
                    resp = get_error_result("WipeMdCopyLvResError")
                    return resp
            
            # 删除配置文件
            cfgFileName = resName + ".res"
            # 备份数据文件，用于回滚
            with open(COPY_LV_CONFIG_PATH + cfgFileName, 'r') as f:
                self.cacheData[cfgFileName] = f.read()

            cfgDictInfo = self.get_lv_copy_file_info(COPY_LV_CONFIG_PATH + cfgFileName)
            os.remove(COPY_LV_CONFIG_PATH + cfgFileName)
            
            # 如果是异步模式，则需要删除异步同步数据策略
            if cfgDictInfo["protocol"] == "A":
                CopyLvAsyncUpdate().remove_async_update_data_job(cfgDictInfo["resName"])

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def delete_remote_lv_copy(self, request):
        try:
            remoteLvPath = request.data.get('remoteLvPath')
            data = {
                "command": "deleteLvCopy",
                "requestEnd": "backend",
                "localLvPath": remoteLvPath,
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def delete_lv_copy(self, request, *args, **kwargs):
        """删除卷复制"""
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            localLvPath = request.data.get('localLvPath')
            # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
            resName = localLvPath.split("/")[-1]            
            
            # 判断是否为双机资源，如果已经是启用的双机资源，则不可以操作
            if self.is_double_control_resource(resName)[1]:
                logger.error("The enabled dual-machine resource, operation prohibited!!!")
                return get_error_result("DualMachineResIsEnabled")
            
            # 1.判断前后是否为前端发起：前端发起还需要处理对端机器
            if requestEnd == "frontend":
                # a、删除本地资源
                resp = self.delete_local_lv_copy(request)
                if resp.get('code') != 0:
                    logger.error("local host delete drbd resource failed!!!")
                    return resp                

                # b、发起对端
                resp = self.delete_remote_lv_copy(request)
                if resp.get('code') != 0:
                    logger.error("peer host delete drbd resource failed!!!")
                    # 执行回滚
                    self.rollback_delete_local_lv_copy(request)
                    return resp                
            else:
                # 删除本地资源
                resp = self.delete_local_lv_copy(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_alter_local_lv_copy(self, request):
        try:
            role = request.data.get('role')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]

            # 归滚节点role
            run_cmd(f"drbdadm {role} {resName}")
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def alter_local_role_lv_copy(self, request):
        """切换本地卷复制角色: primary和secondary角色对掉"""
        try:
            resp = get_error_result("Success")
            role = request.data.get('role')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]

            dstRole = "secondary" if role == "primary" else "primary"
            # 当前节点role切换
            altRoleCmd = "drbdadm %s %s" % (dstRole, resName)
            (status, altRoleCmdOutput) = run_cmd(altRoleCmd)
            if status == 11:
                resp = get_error_result("CopyLvIsBusy")
                return resp
            if status != 0:
                logger.error("Failed to set role for replication logical volume resource!!!")
                resp = get_error_result("SetCopyLvResRoleError")
                return resp
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_alter_remote_lv_copy(self, request):
        try:
            role = request.data.get('role')
            remoteLvPath = request.data.get('remoteLvPath')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:            
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]
            data = {
                "command": "alterRoleLvCopy",
                "requestEnd": "backend",
                "role": role,
                "localLvPath": remoteLvPath,
                "lvName": resName
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def alter_remote_role_lv_copy(self, request):
        """切换远程卷复制角色: primary和secondary角色对掉"""
        try:
            role = request.data.get('role')
            remoteLvPath = request.data.get('remoteLvPath')
            resName = request.data.get('lvName')
            if resName == "" or resName is None:            
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]
            data = {
                "command": "alterRoleLvCopy",
                "requestEnd": "backend",
                "role": "secondary" if role == "primary" else "primary",
                "localLvPath": remoteLvPath,
                "lvName": resName
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def alter_role_lv_copy(self, request, *args, **kwargs):
        """切换卷复制角色: 双机执行primary和secondary角色对掉"""
        try:
            resp = get_error_result("Success")
            role = request.data.get('role')
            requestEnd = request.data.get('requestEnd')  # frontend / backend
            resName = request.data.get('lvName')
            if resName == "" or resName is None:  
                localLvPath = request.data.get('localLvPath')
                # 获取lv的name，直接从lvpath中获取，使用/分割取最后一个字段
                resName = localLvPath.split("/")[-1]
            # 判断是否为双机资源，如果已经是启用的双机资源，则不可以操作
            if self.is_double_control_resource(resName)[1]:
                logger.error("The enabled dual-machine resource, operation prohibited!!!")
                return get_error_result("DualMachineResIsEnabled")

            # 0、首先判断requestEnd接口是浏览器前端请求还是后端请求，前端请求需要处理对端机器的完整流程
            if requestEnd == "frontend":
                # 1、判断当前节点role是否为primary（primary节点必须先切换为secondary）
                if role == "primary":
                    # a、当前节点role切换为secondary
                    resp = self.alter_local_role_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("local host alter drbd role failed!!!")
                        return resp
                    # b、向对端机器发起role切换到primary的http请求
                    resp = self.alter_remote_role_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("peer host alter drbd role failed!!!")
                        # 回滚本地
                        self.rollback_alter_local_lv_copy(request)
                        return resp                    
                else:
                    # a、向对端机器发起role切换到secondary的http请求
                    resp = self.alter_remote_role_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("remote host alter drbd role failed!!!")
                        return resp
                    # b、当前节点role切换为primary
                    resp = self.alter_local_role_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("local host alter drbd role failed!!!")
                        # 回滚对端
                        self.rollback_alter_remote_lv_copy(request)
                        return resp                    
            else:
                # 由于是后端发起的，所以只需要完成当前主机的role切换即可
                resp = self.alter_local_role_lv_copy(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_mount_local_lv_copy(self, request):
        try:
            resName = request.data.get('lvName')
            devicePath = request.data.get('devicePath')

            # 脚本修改需要改回
            resAlterScript = "/etc/keepalived/to_master/drbd_%s.sh" % resName
            if os.path.exists(resAlterScript):
                # 回滚写回原始信息
                with open(resAlterScript, 'w') as f:
                    f.write(self.cacheData[resAlterScript])
            # 执行卸载操作
            getRoleCmd = "drbdadm role %s" % (resName)
            (status, role) = run_cmd(getRoleCmd)
            if role.lower() == "primary":
                run_cmd(f"umount {devicePath}")
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def mount_local_lv_copy(self, request):
        try:
            resp = get_error_result("Success")
            devicePath = request.data.get('devicePath')
            mountDir = request.data.get('mountDir')
            if not mountDir:
                resp = get_error_result("MessageError")
                return resp

            # 如果是drbd的虚拟盘挂载，特殊处理双机资源的故障转移
            resName = request.data.get('lvName')
            # 查找双机资源drbd资源的切换脚本进行修改
            resAlterScript = "/etc/keepalived/to_master/drbd_%s.sh" % resName
            if os.path.exists(resAlterScript):
                # 备份文件，用于回滚
                with open(resAlterScript, 'r') as f:
                    self.cacheData[resAlterScript] = f.read()

                # 对mount这行文本执行替换操作
                replaceText = "mount %s %s" % (devicePath, mountDir)
                replaceText = replaceText.replace("/", "\/")
                sedCmd = "sed -i '/^#*.*mount/s/.*/%s/' %s" % (replaceText, resAlterScript)
                (status, output) = run_cmd(sedCmd)
                if status != 0:
                    logger.error("Failed to execute sed command!!!")
                    resp = get_error_result("ExecuteSedCmdError")
            # 判断当前机器的当前drbd资源是否为primary角色，如果不是primary则不需要进行挂载操作
            getRoleCmd = "drbdadm role %s" % (resName)
            (status, role) = run_cmd(getRoleCmd)
            if status != 0:
                if 'not defined in your config' in role:
                    logger.error("The replication logical volume resource does not exist!!!")
                    resp = get_error_result("CopyLvResourceNotExist")
                    return resp
                elif 'Unknown resource' in role:
                    logger.error("The replication logical volume resource is not started!!!")
                    resp = get_error_result("CopyLvResourceNotStarted")
                    return resp
                else:
                    logger.error("Failed to get replication logical volume resource role!!!")
                    resp = get_error_result("GetCopyLvResourceRoleError")
                    return resp
            # 判断路径是否存在，不存在则创建，连个节点都需要创建挂载点
            if mountDir and not os.path.exists(mountDir):
                os.makedirs(mountDir)
            if role.lower() == "primary":
                cmd = 'mount {} {}'.format(devicePath, mountDir)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if is_include_in_arr(output, ['mount point does not exist', '挂载点不存在']):
                        logger.error("Mount directory does not exist!!!")
                        resp = get_error_result("DirectoryNotExist")
                    elif is_include_in_arr(output, ['already mounted on', '已挂载于']):
                        logger.error("Device is already mounted!!!")
                        resp = get_error_result("AlreadyMounted")
                    elif is_include_in_arr(output, ['wrong fs type', '文件系统类型错误']):
                        logger.error("Please format the device first!!!")
                        resp = get_error_result("FsTypeError")
                    elif is_include_in_arr(output, ["unknown filesystem type 'drbd'", '未知的文件系统类型“drbd”']):
                        logger.error("It is already being used for volume replication and cannot be manipulated!!!")
                        resp = get_error_result("UsedForDrbd")
                    elif is_include_in_arr(output, ['does not exist', '不存在']):
                        logger.error("Mount device does not exist!!!")
                        resp = get_error_result("DeviceNotExist")
                    else:
                        logger.error("Mounting failed!!!")
                        resp = get_error_result("MountError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def mount_remote_lv_copy(self, request):
        try:
            devicePath = request.data.get('devicePath')            
            mountDir = request.data.get('mountDir')     
            lvName = request.data.get('lvName')       
            data = {
                "command": "mountLvCopy",
                "requestEnd": "backend",
                "lvName": lvName,
                "mountDir": mountDir,
                "devicePath": devicePath
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def mount_lv_copy(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')  # frontend / backend

            # 0、首先判断requestEnd接口是浏览器前端请求还是后端请求，前端请求需要处理对端机器的完整流程
            if requestEnd == "frontend":
                # 判断如果drbd的资源是处于连接状态下，才会进行双机操作
                resName = request.data.get('lvName')
                (status, cstate) = run_cmd("drbdadm cstate %s" % resName)
                if status != 0:
                    if 'not defined in your config' in cstate:
                        logger.error("The replication logical volume resource does not exist!!!")
                        resp = get_error_result("CopyLvResourceNotExist")
                        return resp
                    elif 'Unknown resource' in cstate:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to get the connection status of the replication logical volume!!!")
                        resp = get_error_result("GetCopyLvCstateError")
                        return resp
                # b、当前节点
                resp = self.mount_local_lv_copy(request)
                if resp.get('code') != 0:
                    logger.error("local host mount drbd device failed!!!")
                    return resp
                # a、向对端机器的http请求
                # 连接正常才会处理对端机器，否则就是处理本地，把“脱机”情况包含进来了
                if cstate.lower() == "connected":
                    resp = self.mount_remote_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("remote host mount drbd device failed!!!")
                        # 回滚本地
                        self.rollback_mount_local_lv_copy(request)
                        return resp
            else:
                # 由于是后端发起的
                resp = self.mount_local_lv_copy(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_umount_local_lv_copy(self, request):
        try:
            resName = request.data.get('lvName')
            devicePath = request.data.get('devicePath')

            # 脚本修改需要改回
            resAlterScript = "/etc/keepalived/to_master/drbd_%s.sh" % resName
            if os.path.exists(resAlterScript):
                # 回滚写回原始信息
                with open(resAlterScript, 'w') as f:
                    f.write(self.cacheData[resAlterScript])
            # 执行挂载操作
            if self.cacheData.get('mount_dir'):
                run_cmd(f"mount {devicePath} {self.cacheData['mount_dir']}")                
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def umount_local_lv_copy(self, request):
        try:
            resp = get_error_result("Success")
            devicePath = request.data.get('devicePath')
            if devicePath != "":
                # 如果是drbd的虚拟盘挂载，特殊处理双机资源的故障转移
                resName = request.data.get('lvName')
                # 查找双机资源drbd资源的切换脚本进行修改
                resAlterScript = "/etc/keepalived/to_master/drbd_%s.sh" % resName
                if os.path.exists(resAlterScript):
                    # 备份文件，用于回滚
                    with open(resAlterScript, 'r') as f:
                        self.cacheData[resAlterScript] = f.read()

                    # 对mount这行文本执行替换操作
                    replaceText = "##mount"
                    sedCmd = "sed -i '/^#*.*mount/s/.*/%s/' %s" % (replaceText, resAlterScript)
                    (status, output) = run_cmd(sedCmd)
                    if status != 0:
                        logger.error("Failed to execute sed command!!!")
                        resp = get_error_result("ExecuteSedCmdError")
                # 判断如果确实当前机器有挂载drbd虚拟盘，则进行卸载操作
                mount_dir = get_device_mountpoint(devicePath)
                if mount_dir:
                    # 备份挂载路径，用于回滚
                    self.cacheData['mount_dir'] = mount_dir

                    cmd = 'umount {}'.format(devicePath)
                    (status, output) = run_cmd(cmd)
                    if status != 0:
                        if is_include_in_arr(output, ['not mounted', '未挂载']):
                            logger.error("Device not mounted!!!")
                            resp = get_error_result("NotMounted")
                        elif is_include_in_arr(output, ['target is busy', '目标忙']):
                            logger.error("In use by another device!!!")
                            resp = get_error_result("DeviceBusy")
                        else:
                            logger.error("Umounting failed!!!")
                            resp = get_error_result("UmountError")
                    else:
                        # 卸载成功后，可以删除被挂载的目录,这个目录应该是个空目录
                        os.removedirs(mount_dir)
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp        
    
    def umount_remote_lv_copy(self, request):
        try:
            devicePath = request.data.get('devicePath')
            lvName = request.data.get('lvName')       
            data = {
                "command": "umountLvCopy",
                "requestEnd": "backend",
                "lvName": lvName,
                "devicePath": devicePath
            }
            return peer_post("/cluster/doubleCtlStore/lvCopy", data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
       
    def umount_lv_copy(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')  # frontend / backend

            # 0、首先判断requestEnd接口是浏览器前端请求还是后端请求，前端请求需要处理对端机器的完整流程
            if requestEnd == "frontend":
                # 判断如果drbd的资源是处于连接状态下，才会进行双机操作
                resName = request.data.get('lvName')
                (status, cstate) = run_cmd("drbdadm cstate %s" % resName)
                if status != 0:
                    if 'not defined in your config' in cstate:
                        logger.error("The replication logical volume resource does not exist!!!")
                        resp = get_error_result("CopyLvResourceNotExist")
                        return resp
                    elif 'Unknown resource' in cstate:
                        logger.error("The replication logical volume resource is not started!!!")
                        resp = get_error_result("CopyLvResourceNotStarted")
                        return resp
                    else:
                        logger.error("Failed to get the connection status of the replication logical volume!!!")
                        resp = get_error_result("GetCopyLvCstateError")
                        return resp
                # a、当前节点
                resp = self.umount_local_lv_copy(request)
                if resp.get('code') != 0:
                    logger.error("local host umount drbd device failed!!!")
                    return resp                

                # b、向对端机器的http请求
                # 连接正常才会处理对端机器，否则就是处理本地，把“脱机”情况包含进来了
                if cstate.lower() == "connected":                
                    resp = self.umount_remote_lv_copy(request)
                    if resp.get('code') != 0:
                        logger.error("remote host umount drbd device failed!!!")
                        # 执行回滚
                        self.rollback_umount_local_lv_copy(request)
                        return resp                
            else:
                # 由于是后端发起的
                resp = self.umount_local_lv_copy(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp       

    def force_to_standalone(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            localLvPath = request.data.get('localLvPath')
            if localLvPath:
                # 如果是drbd的虚拟盘挂载，特殊处理双机资源的故障转移
                resName = os.path.basename(localLvPath)
                cmd = 'drbdadm disconnect {}'.format(resName)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    logger.error(f"{cmd} {output}!!!")
                    resp = get_error_result("ForceCopyLvToStandaloneFailed")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp  
