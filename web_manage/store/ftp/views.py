import configparser
from enum import Enum
import subprocess
import traceback
import logging
import socket
import os
import ipaddress
import json
import numpy as np
from django.db.models import Q
from django.core.cache import cache
from django.http import Http404, HttpResponseServerError
from drf_yasg import openapi
import pexpect
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
from storesys.timerTasks import get_double_control_status
from web_manage.cluster.models import ClusterNode
from web_manage.common.cmdutils import run_cmd
from web_manage.common.http import peer_post
from web_manage.common.log import insert_operation_log
from web_manage.common.utils import JSONResponse, WebPagination, get_error_result
from web_manage.admin.models import OperationLog
from web_manage.admin.serializers import OperationLogSerializer
from web_manage.store.nas.models import NasUser
from web_manage.store.nas.models import NasDir


logger = logging.getLogger(__name__)

SFTP_CFG = '/etc/vsftpd/vsftpd.conf'

class SftpDirCmd(Enum):
    AddSftp = "addSftp"
    EditSftp = "editSftp"
    DeleteSftp = "deleteSftp"


class SftpDir(APIView):
    """
    ftp管理：ftp信息直接从数据库：nas_dir直接添加一个ftp_user字段，存放nas用户即可
    """
    def get(self,request,*args,**kwargs):
        ret =get_error_result("Success")

        json_arr = []
        try:
            ftpDirs = NasDir.objects.all()
            for ftpDir in ftpDirs:
                nasUser = ftpDir.nas_user
                if not ftpDir.nas_user:
                    continue
                
                item = {
                    'name': ftpDir.name,
                    'path': ftpDir.mountpoint,
                    'user': nasUser.name,
                    'lvpath': os.path.dirname(ftpDir.mountpoint),
                    'valid': os.path.exists(ftpDir.mountpoint + "/" + ftpDir.name),
                    'is_drbd': ftpDir.is_drbd,
                    'is_ftp_active': (bool)(ftpDir.is_ftp_active)
                }
                json_arr.append(item)
            ret['data'] = json_arr
            return JSONResponse(ret)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
 
    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",            
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in SftpDirCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'path': openapi.Schema(type=openapi.TYPE_STRING),
            'user': openapi.Schema(type=openapi.TYPE_STRING),
            'is_ftp_active': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command == "addSftp":
                ret = self.add_sftp(request, args, kwargs)
            elif command == "editSftp":
                ret = self.edit_sftp(request, args, kwargs)
            elif command == "deleteSftp":
                ret = self.delete_sftp(request, args, kwargs)                
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
   
    def add_sftp(self, request, *args, **kwargs):
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
                    resp = self.add_remote_sftp(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.add_local_sftp(request)
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.add_local_sftp(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
            else:
                resp = self.add_local_sftp(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def add_remote_sftp(self, request, *args, **kwargs):
        try:
            dirName = request.data.get("name")
            path = request.data.get("path")
            user = request.data.get("user")
            is_ftp_active = request.data.get("is_ftp_active")

            data = {
                "name": dirName,
                "path": path,
                "user": user,
                "is_ftp_active": is_ftp_active,
                "requestEnd":'backend',
                "command": 'addSftp'
            }
            return peer_post("/store/ftp/add_ftp",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def add_local_sftp(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            path = request.data.get("path")
            user = request.data.get("user")
            is_ftp_active = request.data.get("is_ftp_active")

            # 查询数据库共享目录信息 
            nasDir = NasDir.objects.filter(name=name).first()
            nasUser = NasUser.objects.filter(name=user).first()

            # 判断用户是否正常
            if not nasDir:
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
            # 判断目录是否正常
            if not nasUser:
                resp = get_error_result("OsUserAlreadyExist")
                return resp
            
            if nasUser.is_ftp:
                # 数据库记录已经存在: 如果是对端发起的添加，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("NasUserAlreadyUsedFtp")
                return resp            

            # 目录已经启用ftp共享，则报错
            if nasDir.nas_user:
                resp = get_error_result("FtpUsedTheDir")
                return resp

            # 根据是否激活ftp共享目录：对ftp共享目录和用户绑定关系进行修改
            if is_ftp_active:
                path = path + "/" + name
            else:
                # 用户绑定的主目录修改为空目录：/dev/null
                path = "/dev/null"
            cmd = "usermod -d " + path + " " + user
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                resp = get_error_result("CreateFtpShareError")
                return resp
                        
            # 更新dir目录的数据库为：已经启用ftp共享
            nasDir.nas_user = nasUser
            nasDir.is_ftp_active = is_ftp_active
            nasDir.save()
            nasUser.is_ftp = 1
            nasUser.save()

            # 重载服务配置信息
            os.system('systemctl restart vsftpd')
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def edit_sftp(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            is_ftp_active = request.data.get("is_ftp_active") 
            user = request.data.get("user")  

            #判断ftp正在被连接使用
            if is_ftp_active == False:
                path = "/dev/null"
                cmd = "usermod -d " + path + " " + user
                (status, cmdOutput) = run_cmd(cmd)
                if status == 8 and "used by" in cmdOutput:
                    resp = get_error_result("FtpShareIsBusy")
                    return resp
                elif status != 0:
                    resp = get_error_result("EditFtpShareError")
                    return resp
                            
            
            # 查询数据库，确定当前Nas目录是否为drbd复制路径卷
            nasDir = NasDir.objects.filter(name=name).first()
            is_drbd = True if nasDir and nasDir.is_drbd else False

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend" and is_drbd == True:
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":                                         
                    resp = self.edit_remote_sftp(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.edit_local_sftp(request)
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.edit_local_sftp(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
            else:
                resp = self.edit_local_sftp(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def edit_remote_sftp(self, request, *args, **kwargs):
        try:
            dirName = request.data.get("name")
            path = request.data.get("path")
            user = request.data.get("user")
            is_ftp_active = request.data.get("is_ftp_active")

            data = {
                "name": dirName,
                "path": path,
                "user": user,
                "is_ftp_active": is_ftp_active,
                "requestEnd":'backend',
                "command": 'editSftp'
            }
            return peer_post("/store/ftp/edit_ftp",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def edit_local_sftp(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            path = request.data.get("path")
            old_user = request.data.get("olduser")
            user = request.data.get("user")
            is_ftp_active = request.data.get("is_ftp_active")

            # 查询数据库共享目录信息 
            nasDir = NasDir.objects.filter(name=name).first()
            nasUser = NasUser.objects.filter(name=user).first()


            # 修改用户时候删除前用户的信息
            # oldUser = NasUser.objects.filter(name=old_user).first()
            # oldUser.is_ftp = 0
            # oldUser.save()

            # cmd = "usermod -d /dev/null " + old_user
            # (status, cmdOutput) = run_cmd(cmd)
            # if status == 8 and "used by" in cmdOutput:
            #     resp = get_error_result("FtpShareIsBusy")
                # return resp
            
            # 根据是否激活ftp共享目录：对ftp共享目录和用户绑定关系进行修改
            if is_ftp_active:
                path = path + "/" + name
            else:
                # 用户绑定的主目录修改为空目录：/dev/null
                path = "/dev/null"
            cmd = "usermod -d " + path + " " + user
            (status, cmdOutput) = run_cmd(cmd)
            if status == 8 and "used by" in cmdOutput:
                resp = get_error_result("FtpShareIsBusy")
                return resp
            elif status != 0:
                resp = get_error_result("EditFtpShareError")
                return resp

            # 更新dir目录的数据库为：已经启用ftp共享
            nasDir.nas_user = nasUser
            nasDir.is_ftp_active = is_ftp_active
            nasDir.save()
            nasUser.is_ftp = 1
            nasUser.save()

            # 重载服务配置信息
            os.system('systemctl restart vsftpd')
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
               
    def delete_sftp(self, request, *args, **kwargs):
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
                    resp = self.delete_remote_sftp(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.delete_local_sftp(request)
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.delete_local_sftp(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")                
            else:
                resp = self.delete_local_sftp(request)

            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def delete_remote_sftp(self, request, *args, **kwargs):
        try:
            dirName = request.data.get("name")
            path = request.data.get("path")
            user = request.data.get("user")

            data = {
                "name": dirName,
                "path": path,
                "user": user,
                "requestEnd":'backend',
                "command": 'deleteSftp'
            }
            return peer_post("/store/ftp/delete_ftp",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def delete_local_sftp(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            path = request.data.get("path")
            user = request.data.get("user")

            # 查询数据库共享目录信息
            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                # 数据库记录不存在: 如果是对端发起的删除，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
          
            nasUser = NasUser.objects.filter(name=user).first()
            if not nasUser:
                resp = get_error_result("NasUserRecordNotExsits")
                return resp

            # ftp用户和共享目录解绑定: 这里只是修改一个没有创建的用户主目录，
            path = "/home/" + user
            cmd = "usermod -d " + path + " " + user
            (status, cmdOutput) = run_cmd(cmd)
            if status == 8:
                resp = get_error_result("FtpShareIsBusy")
                return resp
            elif status != 0:
                resp = get_error_result("DeleteFtpShareError")
                return resp
            # 更新dir目录的数据库为：已经启用ftp共享
            nasDir.nas_user = None
            nasDir.save()
            nasUser.is_ftp = 0
            nasUser.save()

            # 重载服务配置信息
            os.system('systemctl restart vsftpd')
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

        
