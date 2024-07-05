import re
import traceback
import logging
import socket
import os
import ipaddress
import json
import numpy as np
from django.http import Http404, HttpResponseServerError
from rest_framework.views import APIView
from storesys.timerTasks import get_double_control_status
from web_manage.cluster.models import ClusterNode
from web_manage.common.constants import NFS_CONFIG_FILE
from web_manage.common.http import peer_post
from web_manage.common.utils import JSONResponse, WebPagination, get_error_result, is_ip_addr, is_netmask
from web_manage.admin.models import OperationLog
from web_manage.admin.serializers import OperationLogSerializer
from drf_yasg import openapi
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema

from web_manage.store.nas.models import NasDir

logger = logging.getLogger(__name__)


def read_exports_file(file_path):
    """
    读取NFS的exports文件，将目录和权限信息存储到字典数组中
    :param file_path: 文件路径
    :return: 字典数组，每个元素包含目录和权限信息
    """
    exports_data = []  # 存储目录和权限信息的数组

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()  # 去除行首尾的空白字符
                if line:
                    activate = 1  # 默认激活
                    if line.startswith("#"):
                        if line[1] == "/":
                            # 去掉井号后的内容
                            line = line[1:]
                            activate = 0 # 未激活
                        else:
                            continue  # 跳过以井号开头但不是以"/"开头的行
                    parts = line.split()  # 按空格分割行
                    if len(parts) >= 2:
                        directory = parts[0]  # 目录
                        permissions = " ".join(parts[1:])  # 权限信息，使用下划线隔开，方便分割
                        exports_data.append({'directory': directory, 'permissions': permissions, 'activate': activate})
    except FileNotFoundError:
        raise FileNotFoundError(f"file {file_path} not exists.")
    return exports_data

def write_exports_file(file_path, exports_data):
    """
    将目录和权限信息从字典数组写入NFS的exports文件
    :param file_path: 文件路径
    :param exports_data: 字典数组，每个元素包含目录和权限信息
    """
    try:
        with open(file_path, 'w') as f:
            for entry in exports_data:
                directory = entry.get('directory', '')
                permissions = entry.get('permissions', '')
                activate = entry.get('activate', 0)
                if directory and permissions:
                    # 启用"激活"
                    if activate:
                        f.write(f"{directory} {permissions}\n")
                    else:
                        f.write(f"#{directory} {permissions}\n")
    except FileNotFoundError:
        raise FileNotFoundError(f"file {file_path} not exists.")


def comb_auth_info(exportation, readwrite):
    '''
    根据输入组配置信息：
    1、exportation 允许IP地址信息：可能是多个ip、或ip网络地址/掩码长
    2、readwrite 读写权限信息，true表示读写，fale表示只读
    '''
    try:
        # 获取权限设置信息
        if readwrite:
            readwrite = 'rw,'
        else:
            readwrite = 'ro,'
        
        # 根据ip设置和权限设置，得到最终权限和ip的配置信息
        ipAuthInfo = ""
        if exportation == ""  or exportation == "所有":
            ipAuthInfo = '*' +  '(' + readwrite +')'
        else:
            # 先使用逗号分割exportation
            ipInfoArr = exportation.strip().split(',')
            for ipInfo in ipInfoArr:
                ipInfo = ipInfo.strip()
                # 如果是ip网络地址,必须带有/数字的，需要判断/前面的地址是否合格的网络地址
                ipInfoValidFlag = True
                if '/' in ipInfo:
                    ipNet = ipInfo.split('/')[0].strip()
                    netMaskLen = int(ipInfo.split('/')[1].strip())
                    if netMaskLen > 0 and netMaskLen < 32 and is_netmask(ipNet):
                        ipInfoValidFlag = True
                else:
                    ipInfoValidFlag =  is_ip_addr(ipInfo)
                if not ipInfoValidFlag:
                    # 返回空表示格式有问题
                    return ""
                ipAuthInfo += ipInfo +  '(' + readwrite +') '
        return ipAuthInfo
    except Exception as err:
        logger.error(''.join(traceback.format_exc()))


class Getnfs(APIView):
    """
    查询所有nfs目录
    """
    def get(self,request,*args,**kwargs):
        try:
            resp =get_error_result("Success")

            json_arr=[]
            cfg = read_exports_file(NFS_CONFIG_FILE)
            for item in cfg:
                nfsname = os.path.basename(item['directory'])
                nasDir = NasDir.objects.filter(name=nfsname).first()
                # exportation 去掉读写权限等信息
                exportation = re.sub(r'\([^)]*\)', '', item['permissions']).replace(' ', ',')
                readwrite = True if 'rw' in item['permissions'] else False
                lvpath = os.path.dirname(item['directory'])
                data = {
                    'nfsname':nfsname,
                    'path':item['directory'],
                    "activate": item['activate'],
                    "exportation":exportation,
                    "readwrite":readwrite,
                    "lvpath": lvpath,
                    "valid": os.path.exists(item['directory']),
                    "is_drbd": nasDir.is_drbd
                }
                json_arr.append(data)
            resp['data'] = json_arr
            return JSONResponse(resp)
        except FileNotFoundError:
            resp = get_error_result("GetFileError")
            logger.error(f'GetFileError FileNotFoundError: {NFS_CONFIG_FILE}')
            return JSONResponse(resp)        
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)
    

class Editor_nfs(APIView):
    """
    编辑nfs配置
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",
        type=openapi.TYPE_OBJECT,
        properties={
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'path': openapi.Schema(type=openapi.TYPE_STRING),
            'mountpoint': openapi.Schema(type=openapi.TYPE_STRING),
            'exportation': openapi.Schema(type=openapi.TYPE_STRING),
            'activate': openapi.Schema(type=openapi.TYPE_INTEGER, enum=[1, 0], description='布尔值，表示是否激活'),
            'readwrite': openapi.Schema(type=openapi.TYPE_INTEGER, enum=[1, 0], description='布尔值，表示是否可写'),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))        
    def post(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            name = request.data.get("name")
            requestEnd = request.data.get('requestEnd')

            # 查询数据库，确定当前Nas目录是否为drbd复制路径卷
            nasDir = NasDir.objects.filter(name=name).first()
            is_drbd = True if nasDir and nasDir.is_drbd else False

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend" and is_drbd == True:
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":                                            
                    resp = self.edit_remote_nfs(request)
                    if resp.get('code') !=0:
                        return JSONResponse(resp)
                    resp = self.edit_local_nfs(request)
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.edit_local_nfs(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
            else:
                resp = self.edit_local_nfs(request)
            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)
    
    def edit_remote_nfs(self, request, *args, **kwargs):
        try:
            name = request.data.get("name")
            path = request.data.get("path")
            activate = request.data.get("activate")
            exportation = request.data.get("exportation")
            readwrite = request.data.get("readwrite")
            mountpoint = request.data.get("mountpoint")

            data = {
                "name": name,
                "path": path,
                "activate": activate,
                "exportation": exportation,
                "readwrite": readwrite,
                "mountpoint":mountpoint,
                "requestEnd": 'backend'
            }
            return peer_post("/store/nfs/editor_nfs",data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def edit_local_nfs(self, request,*args,**kwargs):
        try:
            absPath = request.data.get("path")
            activate = request.data.get("activate")
            exportation = request.data.get("exportation")
            readwrite = request.data.get("readwrite")
            name = request.data.get("name")
            requestEnd = request.data.get("requestEnd")

            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
            # 前端发起的，drbd卷上的无效目录，禁止操作
            # path = nasDir.mountpoint + "/" + nasDir.name
            # if requestEnd == "frontend" and not os.path.exists(path):
            #     resp = get_error_result("InvalidDirError")
            #     return resp

            # 获取信息：共享目录、ip限制、读写权限
            ipAuthInfo = comb_auth_info(exportation, readwrite)
            if not ipAuthInfo:
                resp = get_error_result("IpOrNetError")
                return resp

            # 更新配置文件：先读取文件到数据结构变量中，再把信息追加到数据结构变量中，最后重新写入即可
            cfg = read_exports_file(NFS_CONFIG_FILE)
            for item in cfg:
                if item['directory'] == absPath:
                    item.update({
                        'permissions': ipAuthInfo,
                        'activate': activate
                    })
            write_exports_file(NFS_CONFIG_FILE, cfg)

            # 重载配置
            os.system('systemctl reload nfs')
            resp = get_error_result("Success")
            return resp
        except FileNotFoundError:
            resp = get_error_result("GetFileError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
        
class Add_nfs(APIView):
    """
    添加nfs配置
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'mountpoint': openapi.Schema(type=openapi.TYPE_STRING),
            'exportation': openapi.Schema(type=openapi.TYPE_STRING),
            'activate': openapi.Schema(type=openapi.TYPE_INTEGER, enum=[1, 0], description='布尔值，表示是否激活'),
            'readwrite': openapi.Schema(type=openapi.TYPE_INTEGER, enum=[1, 0], description='布尔值，表示是否可写'),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))    
    def post(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            mountpoint = request.data.get("mountpoint")
            name = request.data.get("name")

            # 查询数据库，确定当前Nas目录是否为drbd复制路径卷
            nasDir = NasDir.objects.filter(name=name).first()
            is_drbd = True if nasDir and nasDir.is_drbd else False
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend" and is_drbd == True:
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.add_remote_nfs(request)
                    if resp.get('code') !=0:
                        return JSONResponse(resp)
                    resp = self.add_local_nfs(request)
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.add_local_nfs(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
            else:
                resp = self.add_local_nfs(request)

            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)
        
    def add_remote_nfs(self, request, *args, **kwargs):
        try:
            name = request.data.get("name")
            mountpoint = request.data.get("mountpoint")
            activate = request.data.get("activate")
            exportation = request.data.get("exportation")
            readwrite = request.data.get("readwrite")

            data = {
                "name": name,
                "mountpoint": mountpoint,
                "activate": activate,
                "exportation": exportation,
                "readwrite": readwrite,
                "requestEnd": 'backend'
            }
            return peer_post("/store/nfs/add_nfs",data)
        except Exception as err:
            resp = get_error_result("OtherError")
            return resp

    def add_local_nfs(self, request,*args,**kwargs):
        try:
            resp = get_error_result("Success")
            name = request.data.get("name")
            mountpoint = request.data.get("mountpoint")
            activate = request.data.get("activate")
            exportation = request.data.get("exportation")
            readwrite = request.data.get("readwrite")
            requestEnd = request.data.get("requestEnd")

            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                resp = get_error_result("NasDirRecordNotExsits")
                return resp

            # 2、判断创建nfs的共享名是否在数据库：必须已经存在，并且is_nfs不为0
            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
            if nasDir.is_nfs:
                # 数据库记录已经存在: 如果是对端发起的添加，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    resp = get_error_result("Success")
                    return resp
                resp = get_error_result("NfsNameAlreadyExists")
                return resp
            
            # 3、获取信息：共享目录、ip限制、读写权限
            absPath = mountpoint + '/' +name
            ipAuthInfo = comb_auth_info(exportation, readwrite)
            if not ipAuthInfo:
                resp = get_error_result("IpOrNetError")
                return resp

            # 写入配置文件：先读取文件到数据结构变量中，再把信息追加到数据结构变量中，最后重新写入即可
            cfg = read_exports_file(NFS_CONFIG_FILE)
            newNfsDir = {
                'directory': absPath, 
                'permissions': ipAuthInfo,
                'activate': activate
            }
            cfg.append(newNfsDir)
            write_exports_file(NFS_CONFIG_FILE, cfg)

            # 修改共享目录数据库信息，表示nfs已经启用在该目录上
            nasDir = NasDir.objects.filter(name=name).first()
            nasDir.is_nfs = 1
            nasDir.save()

            # 重载nfs服务的配置
            os.system('systemctl reload nfs')

            return resp
        except FileNotFoundError:
            resp = get_error_result("GetFileError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp


class Delete_nfs(APIView):
    """
    删除nfs配置
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'path': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))     
    def post(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")

            # 查询数据库，确定当前Nas目录是否为drbd复制路径卷
            nasDir = NasDir.objects.filter(name=name).first()
            is_drbd = True if nasDir and nasDir.is_drbd else False

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend" and is_drbd == True:
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.delete_remote_nfs(request)
                    if resp.get('code') !=0:
                        return JSONResponse(resp)
                    resp = self.delete_local_nfs(request)
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.delete_local_nfs(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
            else:
                resp = self.delete_local_nfs(request)

            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)
        
    def delete_remote_nfs(self, request, *args, **kwargs):
        try:
            path = request.data.get("path")
            name = request.data.get("name")

            data = {
                "name": name,
                "path": path,
                "requestEnd": 'backend'
            }
            return peer_post("/store/nfs/delete_nfs",data)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def delete_local_nfs(self, request,*args,**kwargs):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            absPath = request.data.get("path")
            name = request.data.get("name")

            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                # 数据库记录不存在: 如果是对端发起的删除，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("NasDirRecordNotExsits")
                return resp

            # 过滤掉需要删除的nfs目录记录，更新配置文件 
            cfg = read_exports_file(NFS_CONFIG_FILE)
            cfg = [element for element in cfg if element['directory'] != absPath]
            write_exports_file(NFS_CONFIG_FILE, cfg)

            # 共享目录数据库记录更新is_nfs字段为0,表示该目录没有启用nfs
            nasDir = NasDir.objects.filter(name=name).first()
            nasDir.is_nfs = 0
            nasDir.save()

            # 重载nfs配置
            os.system('systemctl reload nfs')
            resp = get_error_result("Success")
            return resp
        except FileNotFoundError:
            resp = get_error_result("GetFileError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
