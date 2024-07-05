import base64
import configparser
from enum import Enum
import pwd
import re
import shutil
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
import pexpect
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
import psutil
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

def check_user_exists(username):
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False
    except Exception as err:
        logger.error(''.join(traceback.format_exc()))
 
class NasClientMng(APIView):
    """
    查询挂载nas的客户端连接用户
    """
    def get(self,request,*args,**kwargs):
        try:
            resp =get_error_result("Success")

            serves = (21,2049,445)

            data = []

            for port in serves:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.laddr.port == port or (conn.raddr and conn.raddr.port == port):
                        if conn.raddr:
                            if port == 21:
                                ip_address = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', conn.raddr.ip).group(0)
                                Single_data = {'serve':'ftp','ip':ip_address}
                            elif port ==2049:
                                Single_data = {'serve':'nfs','ip':conn.raddr.ip}
                            elif port == 445:
                                Single_data = {'serve':'smb','ip':conn.raddr.ip}
                            
                            data.append(Single_data)

            resp['data'] = data
            return JSONResponse(resp)     
                
        
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetMountUserError")
            return JSONResponse(resp)
        

class NasUserMngCmd(Enum):
    AddGroup = "addGroup"
    DeleteGroup = "deleteGroup"
    AddUser = "addUser"
    EditUser = "editUser"
    DeleteUser = "deleteUser"


class NasUserMng(APIView):
    """
    nas用户操作：添加的是系统用户和用户组，只是只用于nas的用户
    """
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    def get(self,request,*args,**kwargs):
        try:
            resp =get_error_result("Success")
            users = []
            all_data = NasUser.objects.all()
            for item in all_data:
                if item.name != '':
                    data = {'name':item.name,'user_group':item.user_group,'type':item.type}
                    users.append(data)
            resp['data'] = users
            return JSONResponse(resp)     
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetNasUserError")
            return JSONResponse(resp)

    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in NasUserMngCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'user_group': openapi.Schema(type=openapi.TYPE_STRING),
            'password': openapi.Schema(type=openapi.TYPE_STRING),

        },
        required=['command'],
    ))            
    def post(self,request,*args,**kwargs):
        resp = get_error_result("Success")
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
            insert_operation_log(msg, resp["msg"], user_info)
            if command == "addGroup":
                resp = self.add_group(request)
            elif command == "addUser":
                resp = self.add_user(request)
            elif command == "editUser":
                resp = self.edit_user(request)
            elif command == "deleteUser":
                resp = self.delete_user(request)
            elif command == "deleteGroup":
                resp = self.delete_group(request)                
            else:
                resp = get_error_result("MessageError")

            return JSONResponse(resp)
        
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("AddUserError")
            return JSONResponse(resp)

    def add_group(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.add_local_group(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.add_remote_group(request)
                    if resp.get('code') !=0:
                        # 远程失败，则对本地操作进行回滚
                        self.rollback_add_local_group(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.add_local_group(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.add_local_group(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_add_local_group(self, request, *args, **kwargs):
        """
        回滚用户组
        """
        try:
            name = request.data.get("name")
            # 1、删除用户组
            cmd = "groupdel " + name
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                logger.info(f"rollback delete group {name} ok.")
            else:
                logger.error(f"rollback delete group {name} failed.")
            # 2、删除数据库记录
            NasUser.objects.filter(name=name).delete()
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
        
    def add_local_group(self, request, *args, **kwargs):
        """
        添加用户组
        """
        try:
            resp =get_error_result("Success")
            name = request.data.get("name")
            requestEnd = request.data.get('requestEnd')

            nasUser = NasUser.objects.filter(name=name)
            if nasUser:
                # 兼容脱机场景操作导致数据不对称
                if requestEnd == "backend":
                    resp = get_error_result("Success")
                    return resp
                resp = get_error_result("GroupNameAlreadyExists")
                return resp
            else:
                cmd = "groupadd " + name
                (status, cmdOutput) = run_cmd(cmd)
                if status != 0:
                    resp = get_error_result("CreateGroupFailed")
                    return resp
                else:
                    resp = get_error_result("Success")
                    values = {
                            "name": name,
                            "user_group": "",
                            "type": "group"
                        }
                        # 数据插入数据库保存
                    NasUser.objects.create(**values)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_remote_group(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")

            data = {
                "name": name,
                "command": 'addGroup',
                "requestEnd": 'backend'
            }
            return peer_post("/store/nas/nas_user",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

    def delete_group(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.delete_local_group(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.delete_remote_group(request)
                    if resp.get('code') !=0:
                        # 远程失败，则对本地操作进行回滚
                        self.rollback_delete_local_group(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.delete_local_group(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.delete_local_group(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def rollback_delete_local_group(self, request, *args, **kwargs):
        """
        回滚删除用户组
        """
        try:
            name = request.data.get("name")
            # 1、添加用户组
            cmd = "groupadd " + name
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                logger.error(f"rollback add group {name} faild")
            else:
                logger.info(f"rollback add group {name} ok")
            # 2、回滚用户组数据库记录
            nasUser = self.cacheData['nasUser']
            if nasUser:
                nasUser.save()
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))

    def delete_local_group(self, request, *args, **kwargs):
        """
        删除用户组
        """
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")

            # 判断如果该用户组还有其他用户存在，是否强制删除该组
            nasUser = NasUser.objects.filter(user_group=name)
            if nasUser.exists():
                resp = get_error_result("ExistsUsersInTheGroup")
                return resp
            
            nasUser = NasUser.objects.filter(name=name)
            if nasUser.exists():
                # 缓存数据，用于回滚
                self.cacheData['nasUser'] = nasUser
                # 删除数据库记录
                NasUser.objects.filter(name=name, type="group").delete()
            else:
                # 兼容脱机添加的用户组数据，恢复双机后数据不对称问题
                if requestEnd == "backend":
                    resp =get_error_result("Success")
                    return resp
                resp = get_error_result("UserGroupNotExists")
                return resp

            cmd = "groupdel " + name
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                resp = get_error_result("DeleteGroupFailed")
                return resp
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp        

    def delete_remote_group(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")

            data = {
                "name": name,
                "command": 'deleteGroup',
                "requestEnd": 'backend'
            }
            return peer_post("/store/nas/nas_user",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

    def add_user(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.add_local_user(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.add_remote_user(request)
                    if resp.get('code') !=0:
                        # 远程失败，执行本地回滚
                        self.rollback_add_local_user(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.add_local_user(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.add_local_user(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_add_local_user(self, request, *args, **kwargs):
        """
        回滚添加用户
        """
        try:
            name = request.data.get("name")
            # 删除用户
            cmd = 'userdel  ' + name
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                logger.error(f"rollback userdel {name} faild.")
            else:
                logger.info(f"rollback userdel {name} ok.")
            # 删除samba用户
            smbUser = self.cacheData.get('smbUser')
            if smbUser:
                cmd = 'pdbedit -x ' + name
                (status, cmdOutput) = run_cmd(cmd)
                if status != 0:
                    logger.error(f"rollback delete samba {name} faild.")
                else:
                    logger.info(f"rollback delete samba {name} ok.")
            # 删除数据库记录
            NasUser.objects.filter(name=name).delete()
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))

    def add_local_user(self, request, *args, **kwargs):
        """
        添加用户
        """
        try:
            resp =get_error_result("Success")
            name = request.data.get("name")
            user_group = request.data.get("user_group")
            password = request.data.get("password")
            requestEnd = request.data.get("requestEnd")

            nasUser = NasUser.objects.filter(name=name)
            if nasUser.exists():
                # 数据库记录已经存在: 如果是对端发起的添加，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("NameAlreadyExists")
                return resp
            else :
                if check_user_exists(name):
                    resp = get_error_result("UserAlreadyExist")
                    return resp

                cmd = "useradd -G " + user_group + " -M -s /usr/sbin/nologin " + name
                (status, cmdOutput) = run_cmd(cmd)
                if status != 0:
                    resp = get_error_result("AddUserError")
                    return resp
                else:
                    resp = self.user_password(name, password)
                    if resp['code'] != 0 :
                        cmd = 'userdel ' + name
                        (status, cmdOutput) = run_cmd(cmd)
                        if status != 0:
                            resp = get_error_result("DeleteUserError")
                            return resp
                        nasUser = NasUser.objects.filter(name=name).first()
                        if nasUser and nasUser.is_smb:
                            cmd = 'pdbedit -x ' + name
                            (status, cmdOutput) = run_cmd(cmd)
                            if status != 0:
                                resp = get_error_result("DeleteSambaUserError")
                                return resp
                            # 缓存记录，回滚需要删除samba用户
                            self.cacheData['smbUser'] = name
                    else:
                        values = {
                                "name": name,
                                "user_group": user_group,
                                "type": "user",
                                "pwd": base64.b64encode(password.encode('utf-8')).decode('utf-8'),
                                "is_ftp": 0,
                                "is_smb": 0
                            }
                            # 数据插入数据库保存
                        NasUser.objects.create(**values)     
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_remote_user(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")
            user_group = request.data.get("user_group")
            password = request.data.get("password")

            data = {
                "name": name,
                "user_group": user_group,
                "password": password,
                "command": 'addUser',
                "requestEnd": 'backend'
            }
            return peer_post("/store/nas/nas_user",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

    def edit_user(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.edit_local_user(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.edit_remote_user(request)
                    if resp.get('code') !=0:
                        # 对端失败，本地进行回滚
                        self.rollback_edit_local_user(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.edit_local_user(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.edit_local_user(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_edit_local_user(self, request, *args, **kwargs):
        """
         回滚修改用户组和更新密码
        """
        try:
            name = request.data.get("name")
            password = request.data.get("password")

            # 回滚数据库记录：先删除修改后的，然后恢复旧的
            NasUser.objects.filter(name=name).delete()
            nasUser = self.cacheData.get('nasUser')
            if nasUser:
                is_smb = nasUser.is_smb
                nasUser.save()

            # 回滚操作系统密码、samba用户密码的修改
            oldUserPwd = self.cacheData.get('oldUserPwd')
            if oldUserPwd:
                self.user_password(name, password)
                if is_smb:
                    self.modify_samba_user_passwd(name, oldUserPwd)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))

    def edit_local_user(self, request, *args, **kwargs):
        """
        修改用户组和更新密码
        """
        try:
            resp =get_error_result("Success")
            name = request.data.get("name")
            user_group = request.data.get("user_group")
            password = request.data.get("password")

            nasUser = NasUser.objects.filter(name=name).first()
            if nasUser:
                # 记录旧用户信息
                self.cacheData['nasUser'] = nasUser
                self.cacheData['oldUserPwd'] = base64.b64decode(nasUser.pwd.encode('utf-8')).decode('utf-8')
                # 更新系统用户密码
                resp = self.user_password(name, password)
                if resp['code'] == 0 :
                    # 判断如果该用户已经创建samba用户，那也需要更新samba用户密码
                    if nasUser.is_smb:
                        updateSmbPwdOk = self.modify_samba_user_passwd(name, password)
                        if updateSmbPwdOk:
                            # 更新数据库信息
                            nasUser.user_group = user_group
                            nasUser.pwd = base64.b64encode(password.encode('utf-8')).decode('utf-8')
                            nasUser.save;
                        else:
                            logger.error("Failed to update smb passwd!!!")
                            resp = get_error_result("UpdateSmUserPasswdError")
                            return resp
                else:
                    logger.error("Failed to update os passwd!!!")
                    resp = get_error_result("UpdateOsUserPasswdError")
                    return resp
            else:
                resp = get_error_result("OsUserAlreadyExist")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def edit_remote_user(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")
            user_group = request.data.get("user_group")
            password = request.data.get("password")

            data = {
                "name": name,
                "user_group": user_group,
                "password": password,
                "command": 'editUser',
                "requestEnd": 'backend'
            }
            return peer_post("/store/nas/nas_user",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def delete_user(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.delete_local_user(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.delete_remote_user(request)
                    if resp.get('code') !=0:
                        # 远程失败，执行本地回滚
                        self.rollback_delete_local_user(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.delete_local_user(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.delete_local_user(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_delete_local_user(self, request, *args, **kwargs):
        """
        回滚删除用户：
        """
        try:
            name = request.data.get("name")
            # 添加数据库记录
            nasUser = self.cacheData['nasUser']
            if nasUser:
                return
            user_group = nasUser.user_group
            password = base64.b64decode(nasUser.pwd.encode('utf-8')).decode('utf-8')
            nasUser.save()              
            # 添加用户
            cmd = "useradd -G " + user_group + " -M -s /usr/sbin/nologin " + name
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                logger.error("rollback_delete_local_user useradd failed !!!")
            else:
                logger.info("rollback_delete_local_user rollback useradd ok !!!")
            # 更新系统用户密码
            self.user_password(name, password)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))

    def delete_local_user(self, request, *args, **kwargs):
        """
        删除用户
        """
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")

            # 判断用户是否已经创建samba或者ftp共享
            nasUser = NasUser.objects.filter(name=name).first()
            if nasUser:
                # 缓存数据，用于回滚
                self.cacheData['nasUser'] = nasUser
                if nasUser.is_smb:
                    resp = get_error_result("NasUserAlreadyUsedForSamba")
                    return resp
                if nasUser.is_ftp:
                    resp = get_error_result("NasUserAlreadyUsedForFtp")
                    return resp
            else:
                # 兼容脱机添加的用户数据，恢复双机后数据不对称问题
                if requestEnd == "backend":
                    resp =get_error_result("Success")
                    return resp
            cmd = 'userdel  ' + name
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                logger.error("Failed to run userdel!!!")
                resp = get_error_result("DelNasUserError")
                return resp
            else:
                resp = get_error_result("Success")

            # 删除数据库记录
            NasUser.objects.filter(name=name).delete()

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def delete_remote_user(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")

            data = {
                "name": name,
                "command": 'deleteUser',
                "requestEnd": 'backend'
            }
            return peer_post("/store/nas/nas_user",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def modify_samba_user_passwd(self, username, password):
        try:
            child = pexpect.spawn('smbpasswd ' + username)
            index = child.expect('password')
            if index == 0:
                child.sendline(password)
                index = child.expect(["password",pexpect.EOF,pexpect.TIMEOUT])
                if index == 0:
                    child.sendline(password)
                    index = child.expect(["Failed",pexpect.EOF,pexpect.TIMEOUT])
                    if index == 0:
                        return False
                    else:
                        return True
            return False
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            return False
        
    def user_password(self, username, password):
        """
        修改用户密码
        """
        try:
            resp = get_error_result("AddUserError")
            
            child = pexpect.spawn('passwd ' + username,encoding='utf-8')
            index = child.expect(['密码','passwod'])
            if index == 0 or index == 1:
                child.sendline(password)

                index = child.expect(['密码','passwod',pexpect.EOF,pexpect.TIMEOUT])
                if index == 0 or index == 1:
                    child.sendline(password)

                    index = child.expect(['成功','success',pexpect.EOF,pexpect.TIMEOUT])
                    if index == 0 or index == 1:
                        resp =get_error_result("Success")
                    else:
                        resp = get_error_result("ModifyUserPasswdError", errInfo=child.before.strip())
                        logger.error(resp)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("AddUserError")
            return resp
        

class NasDirMngCmd(Enum):
    Create = "create"
    Delete = "delete"


class NasDirMng(APIView):
    """
    管理nas共享目录
    """
    def __init__(self):
        # 实例变量
        self.cacheData = {}

    def get(self,request,*args,**kwargs):
        try:
            resp =get_error_result("Success")
            dirs = []
            all_data = NasDir.objects.all()
            for item in all_data:
                isVaild = os.path.exists(item.mountpoint + "/" + item.name)
                total_space = 0
                free_space = 0
                if isVaild:
                    stat = os.statvfs(item.mountpoint)
                    # 计算磁盘容量（以字节为单位）
                    total_space = stat.f_frsize * stat.f_blocks
                    free_space = stat.f_frsize * stat.f_bavail
                data = {
                    'name':item.name,
                    'mountpoint':item.mountpoint,
                    'is_drbd':item.is_drbd,
                    'dev_path':item.dev_path,
                    'is_nfs':item.is_nfs,
                    'is_smb':item.is_smb,
                    'user': item.nas_user.name if item.nas_user else '',
                    'valid': isVaild,
                    'total_space': total_space,
                    'free_space': free_space
                }
                dirs.append(data)
            resp['data'] = dirs
            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)

    @swagger_auto_schema(request_body=openapi.Schema(
        method="post",        
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in NasDirMngCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'name': openapi.Schema(type=openapi.TYPE_STRING),
            'is_drbd': openapi.Schema(type=openapi.TYPE_STRING),
            'dev_path': openapi.Schema(type=openapi.TYPE_STRING),
            'mountpoint': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['command'],
    ))            
    def post(self,request,*args,**kwargs):
        resp = get_error_result("Success")
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
            insert_operation_log(msg, resp["msg"], user_info)
            if command == "create":
                resp = self.add_dir(request, args, kwargs)
            elif command == "delete":
                resp = self.delete_dir(request, args, kwargs)
            else:
                resp = get_error_result("MessageError")
            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)
        
    def add_dir(self, request, *args, **kwargs):
        try:
            resp =get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            is_drbd = request.data.get("is_drbd")
            
            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend" and is_drbd == True:
                # 根据当前双机状态区分调用
                dcStatus = get_double_control_status()
                if dcStatus == "normalDoubleControl":
                    resp = self.add_local_dir(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.add_remote_dir(request)
                    if resp.get('code') !=0:
                        # 对端失败，回滚本地操作
                        self.rollback_add_local_dir(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.add_local_dir(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.add_local_dir(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def rollback_add_local_dir(self, request, *args, **kwargs):
        try:
            name = request.data.get("name")
            # 删除数据库记录
            NasDir.objects.filter(name=name).delete()
        except Exception as err:
            logger.error(f"rollback_add_local_dir error: {err}")
            logger.error(''.join(traceback.format_exc()))

    def add_local_dir(self, request, *args, **kwargs):
        """
        添加nas目录
        """
        try:
            resp =get_error_result("Success")
            name = request.data.get("name")
            is_drbd = request.data.get("is_drbd")
            dev_path = request.data.get("dev_path")
            mountpoint = request.data.get("mountpoint")
            is_drbd = request.data.get("is_drbd")
            requestEnd = request.data.get("requestEnd")
            
            # 1、判断数据库是否已经有记录需要新建的目录
            nasDir = NasDir.objects.filter(name=name)
            if nasDir:
                # 数据库记录已经存在: 如果是对端发起的添加，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("DirAlreadyExists")
                return resp

            # 2、对需要创建的目录进行检查、没有则新建
            needCreateDir = True
            if is_drbd == True:
                resName = os.path.basename(dev_path)
                (status, cmdOutput) = run_cmd(f"drbdadm role {resName}")
                if status == 0 and cmdOutput == "Primary":
                    needCreateDir = True
                else:
                    needCreateDir = False
            
            # 3、判断目录是否需要创建：逻辑卷是否已经挂载
            if needCreateDir:
                # 需要创建目录，判断逻辑卷是否已经挂载，没有挂载则不能用于创建目录
                if not os.path.exists(mountpoint):
                    resp = get_error_result("LvMustMounted")
                    return resp
                # 在挂载点下创建目录
                path = mountpoint + '/' +name
                if not os.path.isdir(path):
                    cmd = "mkdir -m 667 " + path
                    (status, cmdOutput) = run_cmd(cmd)
                    if status != 0:
                        resp = get_error_result("AddNasDirError")
                        return resp
                
            # 4、插入数据库记录
            values = {
                "name": name,
                "mountpoint": mountpoint,
                "is_nfs": 0,
                "is_smb": 0,
                "is_drbd": is_drbd,
                "dev_path": dev_path,
            }
            NasDir.objects.create(**values)

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    def add_remote_dir(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")
            is_drbd = request.data.get("is_drbd")
            dev_path = request.data.get("dev_path")
            mountpoint = request.data.get("mountpoint")

            data = {
                "name": name,
                "dev_path": dev_path,
                "is_drbd": is_drbd,
                "mountpoint": mountpoint,
                "requestEnd":'backend',
                "command": 'create'
            }
            return peer_post("/store/nas/nas_dir",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

    def delete_dir(self, request, *args, **kwargs):
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
                    resp = self.delete_local_dir(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.delete_remote_dir(request)
                    if resp.get('code') != 0:
                        # 执行本地回滚
                        self.rollback_delete_local_dir(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.delete_local_dir(request)
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.delete_local_dir(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

    def rollback_delete_local_dir(self, request):
        '''
        回滚删除共享目录接口：
        1、删除共享目录接口，没有删除数据文件，只是记录了缓存删除目录信息
        '''
        try:
            # 恢复这次请求删除数据库记录前缓存数据
            nasDir = self.cacheData['nasDir']
            if nasDir:
                nasDir.save()
        except Exception as err:
            logger.error(f"rollback_add_local_dir error: {err}")
            logger.error(''.join(traceback.format_exc()))

    def delete_local_dir(self, request, *args, **kwargs):
        """
        删除nas目录
        """
        try:
            resp =get_error_result("Success")
            name = request.data.get("name")
            is_del_data = request.data.get("is_del_data")
            requestEnd = request.data.get('requestEnd')

            is_nsf = 0
            is_smb = 0

            # 1、获取数据库记录，
            nasDir = NasDir.objects.filter(name=name).first()
            if nasDir:
                # 缓存数据库记录，用于双机回滚
                self.cacheData['nasDir'] = nasDir
                mountpoint = nasDir.mountpoint
                is_nsf = nasDir.is_nfs
                is_smb = nasDir.is_smb
                ftp_user_id = nasDir.nas_user.id if nasDir.nas_user else None
            else:
                # 数据库记录不存在: 如果是对端发起的删除，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
                
            # 2、判断该目录是否已经有nas服务使用
            if is_nsf:
                resp = get_error_result("NfsUsedTheDir")
                return resp
            if is_smb:
                resp = get_error_result("SmbNfsUsedTheDir")
                return resp
            if ftp_user_id:
                resp = get_error_result("FtpUsedTheDir")
                return resp

            # 3、根据用户选择是否需要强制删除目录和数据
            path = mountpoint + '/' +name
            if is_del_data and os.path.exists(path):
                shutil.rmtree(path)

            # 4、删除数据库记录
            NasDir.objects.filter(name=name).delete()

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def delete_remote_dir(self, request, *args, **kwargs):
        try:            
            name = request.data.get("name")
            is_del_data = request.data.get("is_del_data")

            data = {
                "name": name,
                "is_del_data": is_del_data,
                "requestEnd":'backend',
                "command": 'delete'
            }
            return peer_post("/store/nas/nas_dir",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret        