import base64
import configparser
from enum import Enum
import traceback
import logging
import os
from drf_yasg import openapi
import pexpect
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from storesys.timerTasks import get_double_control_status
from web_manage.common.cmdutils import run_cmd
from web_manage.common.log import insert_operation_log
from web_manage.common.utils import JSONResponse, WebPagination, get_error_result
from web_manage.admin.models import OperationLog
from web_manage.admin.serializers import OperationLogSerializer
from web_manage.cluster.models import *
from web_manage.common.http import peer_post
from web_manage.store.nas.models import NasDir
from web_manage.store.nas.models import NasUser


logger = logging.getLogger(__name__)

SAMBA_CFG = '/etc/samba/smb.conf'

class SambaDirCmd(Enum):
    AddSamba = "addSamba"
    EditSamba = "editSamba"
    DeleteSamba = "deleteSamba"


class SambaDir(APIView):
    """
    samba配置管理
    """
    def get(self,request,*args,**kwargs):
        ret =get_error_result("Success")

        json_arr = []
        try:
            cfg = configparser.ConfigParser()
            cfg.read(SAMBA_CFG)
            sections = cfg.sections()
            for section in sections:
                if section == 'global':
                    continue
                nasDir = NasDir.objects.filter(name=section).first()
                activate = cfg.get(section, 'available', fallback='yes')
                public = cfg.get(section, 'public', fallback='no')
                writeable = cfg.get(section, 'writeable', fallback='no')
                users = cfg.get(section, 'valid users', fallback='')
                path = cfg.get(section, 'path', fallback='')
                item = {
                    'name': section,
                    'path': path,
                    'activate': 1 if activate == 'yes' else 0,
                    'users': [u[1:] for u in users.split(',') if u.strip() != ''], # @user1,@user2
                    'writeable': 1 if writeable == 'yes' else 0,
                    'public': 1 if public == "yes" else 0,
                    'lvpath': os.path.dirname(path),
                    'valid': os.path.exists(path),
                    'is_drbd': nasDir.is_drbd
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
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in SambaDirCmd.__members__.values()]),
            'requestEnd': openapi.Schema(type=openapi.TYPE_STRING, enum=["frontend", "backend"]),
            'path': openapi.Schema(type=openapi.TYPE_STRING),
            'activate': openapi.Schema(type=openapi.TYPE_INTEGER, enum=[1, 0], description='布尔值，表示是否激活'),
            'writeable': openapi.Schema(type=openapi.TYPE_INTEGER, enum=[1, 0], description='布尔值，表示是否可写'),
            'users': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='数组'),
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
            if command == "addSamba":
                ret = self.add_samba(request, args, kwargs)
            elif command == "editSamba":
                ret = self.edit_samba(request, args, kwargs)
            elif command == "deleteSamba":
                ret = self.delete_samba(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
        
    def add_samba(self, request, *args, **kwargs):
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
                    resp = self.add_remote_samba(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.add_local_samba(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.add_local_samba(request)
                    return resp
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.add_local_samba(request)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def add_remote_samba(self, request, *args, **kwargs):
        try:
            name = request.data.get("name")
            path = request.data.get("path")
            activate = request.data.get("activate")
            writeable = request.data.get("writeable")
            public = request.data.get("public")

            users = request.data.get("users")
            # 去掉传入为None的元素
            users = [u for u in users if u]

            data = {
                "name": name,
                "path": path,
                "activate": activate,
                "public": public,
                "writeable": writeable,
                "users": users,
                "requestEnd":'backend',
                "command": 'addSamba'
            }
            return peer_post("/store/samba/add_smb",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def add_local_samba(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            path = request.data.get("path")
            activate = request.data.get("activate")
            public = request.data.get("public")
            writeable = request.data.get("writeable")
            users = request.data.get("users")
            # 去掉传入为None的元素
            users = [u for u in users if u]

            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
            if nasDir.is_smb:
                # 数据库记录已经存在: 如果是对端发起的添加，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("SambaNameAlreadyExists")
                return resp            

            cfg = configparser.ConfigParser()
            cfg.read(SAMBA_CFG)
            # 判断是否已经有添加过共享目录section
            if cfg.has_section(name):
                logger.error(f"samba config already exists {name}")
                resp = get_error_result("SambaNameAlreadyExists")
                return resp
            cfg.add_section(name)
            cfg.set(name, 'path', path)
            cfg.set(name, 'available', 'yes' if activate == 1 else 'no')
            cfg.set(name, 'writeable', 'yes' if writeable == 1 else 'no')
            cfg.set(name, 'public', 'yes' if public == 1 else 'no')
            # 用户前面需要添加 @符号，多个用户使用逗号隔开
            validUsers = ""
            for user in users:
                validUsers += '@' + user + ","
            cfg.set(name, 'valid users', validUsers)
            with open(SAMBA_CFG, 'w') as cfgFile:
                cfg.write(cfgFile)

            # 更新Nas目录数据库记录该目录已经用于samba: smb目录使用计数
            nasDir = NasDir.objects.filter(name=name).first()
            nasDir.is_smb += 1
            nasDir.save()

            # 更新Nas用户数据库记录该用户已经用于samba: smb用户使用计数
            for user in users:
                nasUser = NasUser.objects.filter(name=user).first()
                password = base64.b64decode(nasUser.pwd.encode('utf-8')).decode('utf-8')
                # 判断如果没有samba共享目录使用到该samba用户了，如果samba还没有使用过这个user，则使用samba用户管理命令添加该用户
                if nasUser.is_smb == 0:
                    retFlag = self.add_samba_user(user, password)
                    if retFlag:
                        logger.info(f'add samba user {user} success.')
                    else:
                        logger.error(f'add samba user {user} failed.')
                # 修改Nas用户使用计数
                nasUser.is_smb += 1
                nasUser.save()

            # 重载服务配置信息
            os.system('systemctl restart smb')
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def delete_samba(self, request, *args, **kwargs):
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
                    resp = self.delete_remote_samba(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.delete_local_samba(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.delete_local_samba(request)
                    return resp
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.delete_local_samba(request)
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def delete_remote_samba(self, request, *args, **kwargs):
        try:
            name = request.data.get("name")
            data = {
                "requestEnd": 'backend',
                "name": name,
                "command": 'deleteSamba'
            }
            return peer_post("/store/samba/delete_smb",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def delete_local_samba(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            name = request.data.get("name")
            requestEnd = request.data.get('requestEnd')

            # 目录不存在直接返回报错
            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                # 数据库记录不存在: 如果是对端发起的删除，兼容脱机运行添加的操作，可以直接成功返回
                if requestEnd == "backend":
                    return resp
                resp = get_error_result("NasDirRecordNotExsits")
                return resp

            cfg = configparser.ConfigParser()
            cfg.read(SAMBA_CFG)

            # 获取该samba共享目录相关信息
            validUsers = cfg.get(name, 'valid users', fallback='')
            users = []
            if validUsers:
                tmpUsers = validUsers.split(',')
                users = [u[1:] for u in tmpUsers if u.strip() != '']
            # 删除该samba共享目录配置信息
            cfg.remove_section(name)
            with open(SAMBA_CFG, 'w') as cfgFile:
                cfg.write(cfgFile)

            # 更新Nas目录数据库记录该目录已经用于samba: smb目录使用计数
            nasDir = NasDir.objects.filter(name=name).first()
            nasDir.is_smb -= 1
            nasDir.save()

            # 更新Nas用户数据库记录该用户已经用于samba: smb用户使用计数
            for user in users:
                nasUser = NasUser.objects.filter(name=user).first()
                nasUser.is_smb -= 1
                nasUser.save()
                # 判断如果没有samba共享目录使用到该samba用户了，就是使用samba用户管理命令删除该用户
                if nasUser.is_smb == 0:
                    retFlag = self.delete_samba_user(user)
                    if retFlag:
                        logger.info(f'delete samba user {user} success.')
                    else:
                        logger.error(f'delete samba user {user} failed.')
            # 重载配置
            os.system('systemctl restart smb')
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret

    def edit_samba(self, request, *args, **kwargs):
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
                    resp = self.edit_remote_samba(request)
                    if resp.get('code') !=0:
                        return resp
                    resp = self.edit_local_samba(request)
                    return resp
                elif dcStatus in ["singleNode", "standAlone"]:
                    resp = self.edit_local_samba(request)
                    return resp
                else:
                    resp = get_error_result("DoubleHaStatusError")
                    return resp
            else:
                resp = self.edit_local_samba(request)

            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
    
    def edit_remote_samba(self, request, *args, **kwargs):
        try:
            name = request.data.get("name")
            path = request.data.get("path")
            activate = request.data.get("activate")
            writeable = request.data.get("writeable")
            public = request.data.get("public")
            users = request.data.get("users")

            data = {
                "name": name,
                "path": path,
                "activate": activate,
                "public": public,
                "writeable": writeable,
                "users": users,
                "requestEnd":'backend',
                "command": 'editSamba'
            }
            return peer_post("/store/samba/editor_smb",data)
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("Executionerroronthepeerend")
            return ret
        
    def edit_local_samba(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            requestEnd = request.data.get('requestEnd')
            name = request.data.get("name")
            activate = request.data.get("activate")
            public = request.data.get("public")
            writeable = request.data.get("writeable")
            users = request.data.get("users")
            # 去掉传入为None的元素
            users = [u for u in users if u]

            nasDir = NasDir.objects.filter(name=name).first()
            if not nasDir:
                resp = get_error_result("NasDirRecordNotExsits")
                return resp
            
            # 前端发起的，drbd卷上的无效目录，禁止操作
            # if requestEnd == 'frontend':
            #     path = nasDir.mountpoint + "/" + nasDir.name
            #     if not os.path.exists(path):
            #         resp = get_error_result("InvalidDirError")
            #         return resp
            
            cfg = configparser.ConfigParser()
            cfg.read(SAMBA_CFG)
            oldValidUsers = cfg.get(name, 'valid users', fallback='')
            oldUsers = []
            if oldValidUsers:
                tmpUsers = oldValidUsers.split(',')
                oldUsers = [u[1:] for u in tmpUsers if u.strip() != '']            
            cfg.set(name, 'available', 'yes' if activate == 1 else 'no')
            cfg.set(name, 'writeable', 'yes' if writeable == 1 else 'no')
            cfg.set(name, 'public', 'yes' if public == 1 else 'no')
            # 用户前面需要添加 @符号，多个用户使用逗号隔开
            validUsers = ""
            for user in users:
                if user:
                    validUsers += '@' + user + ","
            cfg.set(name, 'valid users', validUsers)
            with open(SAMBA_CFG, 'w') as cfgFile:
                cfg.write(cfgFile)

            # a、先处理旧的samba用户
            for user in oldUsers:
                nasUser = NasUser.objects.filter(name=user).first()
                nasUser.is_smb -= 1
                nasUser.save()
                # 判断如果没有samba共享目录使用到该samba用户了，就是使用samba用户管理命令删除该用户
                if nasUser.is_smb == 0:
                    retFlag = self.delete_samba_user(user)
                    if retFlag:
                        logger.info(f'delete samba user {user} success.')
                    else:
                        logger.error(f'delete samba user {user} failed.')
            # b、处理新的smaba用户
            for user in users:
                nasUser = NasUser.objects.filter(name=user).first()
                password = base64.b64decode(nasUser.pwd).decode()
                # 判断如果没有samba共享目录使用到该samba用户了，如果samba还没有使用过这个user，则使用samba用户管理命令添加该用户
                if nasUser.is_smb == 0:
                    retFlag = self.add_samba_user(user, password)
                    if retFlag:
                        logger.info(f'add samba user {user} success.')
                    else:
                        logger.error(f'add samba user {user} failed.')
                # 修改Nas用户使用计数
                nasUser.is_smb += 1
                nasUser.save()

            # 重载服务配置信息
            os.system('systemctl restart smb')
            return resp
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return ret
        
    def add_samba_user(self, username, password):
        try:
            # 把OS用户添加为smaba用户，并且设置samba用户密码（和操作系统用户密码是分开的,为了简化，都使用同一个密码）
            child = pexpect.spawn('smbpasswd -a ' + username)
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
        
    def delete_samba_user(self, username):
        try:
            cmd = 'smbpasswd -x ' + username
            (status, cmdOutput) = run_cmd(cmd)
            if status != 0:
                return False
            return True
        except Exception as err:
            logger.error(err)
            logger.error(''.join(traceback.format_exc()))
            return False
