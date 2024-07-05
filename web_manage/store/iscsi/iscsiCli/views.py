import subprocess
import traceback
import logging
import socket
import os
import json
import numpy as np
from django.http import Http404, HttpResponseServerError
import pexpect
from rest_framework.views import APIView
from web_manage.common.cmdutils import run_cmd
from web_manage.common.utils import JSONResponse, WebPagination, get_error_result, get_ipv4_addresses, is_ip_addr
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


logger = logging.getLogger(__name__)
        


class ScanTarget(APIView):
    """
    获取远程iSCSI target列表信息
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'ipAndPort': openapi.Schema(type=openapi.TYPE_STRING, description='查询远程主机的ip和port，例如：192.168.0.12 或者 192.168.0.12:3260'),
        },
        required=['ipAndPort'],
    ))    
    def post(self, request, *args, **kwargs):
        try:
            ret =get_error_result("Success")
            ipAndPort = request.data.get("ipAndPort")
                          
            # 判断输入ip地址不是空，并且有效；为空或者无效则退出
            ipInput = ipAndPort
            if ':' in ipAndPort:
                ipInput = ipAndPort.split(":")[0]            
            if not ipAndPort or not is_ip_addr(ipInput):
                ret = get_error_result("IpAdrressInfoError")
                return JSONResponse(ret)
            
            # 判断ip地址是否为本地ip地址，不能添加本机自己提供的target
            allIpv4 = get_ipv4_addresses()
            if ipInput in allIpv4:
                ret = get_error_result("ProhibitLocalIscsi")
                return JSONResponse(ret)
                    
            # 根据给定的ip，扫描该ip上存在的所有target，并把信息返回
            data = []
            cmd = 'iscsiadm -m discovery -t st -p ' + ipAndPort
            (status, shuju) = run_cmd(cmd)
            if status != 0 :
                logger.error('get iscsi Detail :'+ shuju)
                ret = get_error_result("GetIscsiDetailError")
                return JSONResponse(ret)

            
            result = shuju.split('\n')
            if len(result) == 0:
                ret = get_error_result("ThisIpNoneIscsi")
                return JSONResponse(ret)
            for element in result:
                ip = element.split(':')[0]
                if not is_ip_addr(ip):
                    continue
                if ip == ipInput:
                    Isc = {'ipAndPort': element.split(',')[0], 'targetName': element.split()[1]}
                    data.append(Isc)

            ret['data'] = data
            return JSONResponse(ret)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


class GetAllSessions(APIView):
    """
    获取已连接的iscsi会话
    """
    def get(self, request, *args, **kwargs):
        try:
            ret =get_error_result("Success")

            cmd = 'iscsiadm -m session'
            (status, output) = subprocess.getstatusoutput(cmd)
            if status == 21:
                # 没会话数据，直接返回
                return JSONResponse(ret)
            elif status != 0:
                logger.error(f"execute {cmd} error!!!")
                ret = get_error_result("SystemError")
                return JSONResponse(ret)
            result = output.split('\n')
            data = []
            for element in result:
                arrList = element.split()
                if not arrList or arrList[0] != 'tcp:':
                    continue
                sessionId = arrList[1].strip('[]')
                ipAndPort = arrList[2].split(',')[0]
                targetName = arrList[3]
                sessionInfo = {'sessionId': sessionId, 'ipAndPort': ipAndPort, 'targetName': targetName}
                data.append(sessionInfo)
            ret['data'] = data
            return JSONResponse(ret)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
        

class CreateSession(APIView):
    """
    连接远程iSCSI target
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'targetName': openapi.Schema(type=openapi.TYPE_STRING, description='target名称'),
            'ipAndPort': openapi.Schema(type=openapi.TYPE_STRING, description='target对应连接的ip和port，例如：192.168.0.12:3260'),
            'enableChap': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='bool值，是否启用CHAP认证，也即用户密码认证'),
            'username': openapi.Schema(type=openapi.TYPE_STRING, description='启用CHAP认证：需要输入用户名'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='启用CHAP认证：需要输入用户密码'),
        },
        required=['targetName', 'ipAndPort', 'enableChap'],
    ))        
    def post(self, request, *args, **kwargs):
        try:
            targetName = request.data.get("targetName")
            ipAndPort = request.data.get("ipAndPort")
            enableChap = request.data.get("enableChap")
            username = request.data.get("username")
            password = request.data.get("password")

            # 设置文件中登录信息：用户密码的修改
            self.setLoginInfo(request,enableChap, username, password)


            #连接所选iscsi
            cmd = 'iscsiadm -m node -T ' + targetName +' -p ' + ipAndPort + ' -l'
            status,data = run_cmd(cmd)
            if status != 0 :
                logger.error('Join iscsi Error :'+ data)
                ret = get_error_result("ConnectIscsiTargetFailed")
                return JSONResponse(ret)
            for element in data.split('\n'):
                if "successful" in element:
                    # 登录成功返回
                    ret =get_error_result("Success")
                    return JSONResponse(ret)
                
            # 登录失败返回 
            ret =get_error_result("ConnectIscsiTargetFailed")
            return JSONResponse(ret)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def setLoginInfo(self,request, enableChap, username, password):
        try:
            targetName = request.data.get("targetName")
            ipAndPort = request.data.get("ipAndPort")
            
            # 设置用户名和密码
            cmd = 'iscsiadm -m node -T '+targetName+' -p '+ipAndPort+' --op update -n node.session.auth.authmethod -v CHAP'
            os.system(cmd)
            cmd = 'iscsiadm -m node -T '+targetName+' -p '+ipAndPort+' --op update -n node.session.auth.username -v '+username
            os.system(cmd)
            cmd = 'iscsiadm -m node -T '+targetName+' -p '+ipAndPort+' --op update -n node.session.auth.password -v '+password
            os.system(cmd)

        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            logger.error(f"setLogin {err}")


class DeleteSession(APIView):
    """
    删除iscsi target会话
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'targetName': openapi.Schema(type=openapi.TYPE_STRING, description='target名称'),
            'ipAndPort': openapi.Schema(type=openapi.TYPE_STRING, description='target对应连接的ip和port，例如：192.168.0.12:3260'),
            'sessionId': openapi.Schema(type=openapi.TYPE_STRING, description='target连接的会话ID'),
        },
        required=['targetName', 'ipAndPort', 'sessionId'],
    ))        
    def post(self, request, *args, **kwargs):
        try:
            ret =get_error_result("Success")
            targetName = request.data.get("targetName")
            ipAndPort = request.data.get("ipAndPort")
            sessionId = request.data.get("sessionId")

            # 根据会话信息，查找这个会话连接的target是使用了哪些lun，
            cmd = 'iscsiadm -m session -r ' + sessionId + ' -P 3'
            content = run_cmd(cmd)[1].split('\n')
            # 如果连接的target里面的lun逻辑卷单元已经被使用，则提示用户无法删除
            for element in content:
                if "Attached scsi disk" in element:
                    disk_data = element.split()
                    disk = '/dev/' + disk_data[3]
                    # 判断是否用于LVM的物理卷
                    cmd = 'pvs'
                    pvs =  run_cmd(cmd)[1].split('\n')
                    for lvm in pvs:
                        if disk in lvm:
                            ret = get_error_result("ThisDeviceWorksInVg")
                            return JSONResponse(ret)
                    # 判断是否用于软磁阵
                    cmd = 'cat /etc/mdadm.conf'
                    raids = run_cmd(cmd)[1].split('\n')
                    for raid in raids:
                        if disk in raid:
                            ret = get_error_result("ThisDeviceWorksInRaid")
                            return JSONResponse(ret)
            # 删除会话
            cmd = 'iscsiadm -m node -T ' + targetName +' -p ' + ipAndPort + ' -u'
            (status, result) = run_cmd(cmd)
            if status != 0 :
                logger.error('delete iscsi errot :'+ result)
                ret = get_error_result("FailedToDeleteIscsi")
                return JSONResponse(ret)

            return JSONResponse(ret)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


class GetSessionDetail(APIView):
    """
    iscsi target 会话详情
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'sessionId': openapi.Schema(type=openapi.TYPE_STRING, description='target连接的会话ID'),
        },
        required=['sessionId'],
    ))          
    def post(self, request, *args, **kwargs):
        try:
            ret =get_error_result("Success")
            sessionId = request.data.get("sessionId")

            cmd = 'iscsiadm -m session -r ' + sessionId + ' -P 3'
            status,content = run_cmd(cmd)
            if status != 0 :
                logger.error('get iscsi Detail :'+ content)
                ret = get_error_result("GetIscsiDetailError")
                return JSONResponse(ret)

            ipadd = ''
            disk = ''
            data = []
            for element in content.split('\n'):
                if "Iface IPaddress" in element:
                    ipadd_data = element.split(':')
                    ipadd = ipadd_data[1]
                if "Attached scsi disk" in element:
                    disk_data = element.split()
                    disk = disk + '/dev/' + disk_data[3] + ';'

            if not disk:
                disk = 'NO storage'
            data = {'ipadd':ipadd,'disk':disk}
            ret['data'] = data
            return JSONResponse(ret)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
