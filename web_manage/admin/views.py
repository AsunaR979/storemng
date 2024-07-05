from enum import Enum
import logging
import base64
import traceback
import hashlib
import time
import base64

from web_manage.common.cmdutils import run_cmd
from web_manage.common.constants import SYS_DEVICE_PATH
from web_manage.common.http import activate_post
from .serializers import *
from web_manage.common.utils import JSONResponse, WebPagination, Authentication, Permission, create_md5, \
                            get_error_result
from web_manage.common.log import insert_operation_log
from rest_framework.views import APIView
from django.utils import timezone
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from django.core.cache import cache
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


logger = logging.getLogger(__name__)


class LoginMix(object):

    authentication_classes = [Authentication, ]  # 添加认证
    permission_classes = [Permission, ]


def make_token(user):
    ctime = str(time.time())
    hash = hashlib.md5(user.encode("utf-8"))
    hash.update(ctime.encode("utf-8"))
    return hash.hexdigest()

# AES解密数据
def ase_decrypt(keyStr, ivStr, encDataStr):
    # key、iv，都使用base64进行转为字符串
    key = base64.b64decode(keyStr.encode('utf-8'))
    iv = base64.b64decode(ivStr.encode('utf-8'))
    encData = base64.b64decode(encDataStr.encode('utf-8'))

    # 创建一个新的 cipher 对象用于解密，它使用相同的密钥和之前用于加密的 IV
    decipher = AES.new(key, AES.MODE_CBC, iv=iv)
    unpadder = lambda x: unpad(x, AES.block_size)
    decryptedData = unpadder(decipher.decrypt(encData))  # 解密数据并去除填充
    return decryptedData.decode()

# 使用密钥解密数据：注意输入的都是b字节码的字符串
def decrypt_data(key, encryptedData):
    key = key.encode('utf-8')
    encryptedData = encryptedData.encode('utf-8')
    cipherSuite = Fernet(key)
    decryptedData = cipherSuite.decrypt(encryptedData).decode('utf-8')
    return decryptedData

def get_system_uuid():
    try:
        uuid = ""
        with open('/sys/class/dmi/id/product_uuid', 'r') as uuid_file:
            uuid = uuid_file.read().strip()
                # 增加cpu的id值
        (status, output) = run_cmd("dmidecode -t processor")
        if status == 0:
            match = re.search(r'ID:\s+([0-9A-Fa-f\s]+)', output, flags=re.DOTALL)
            uuid += match.group(1).replace(' ','').strip() if match else ""
        # 增加操作系统硬盘的序列号
        (status, output) = run_cmd(f"hdparm  -I {SYS_DEVICE_PATH}")
        if status == 0:
            match = re.search(r'Serial Number:\s+([0-9A-Za-z]+)', output, flags=re.DOTALL)
            uuid += match.group(1).replace(' ','').strip() if match else ""        
        return uuid
    except Exception as err:
        logger.error(f"get_system_uuid error: {err}")
        logger.error(''.join(traceback.format_exc()))

def validate_token(obj):
    try:
        # 解析数据信息，得到加密的机器码
        data1 = decrypt_data(obj.key3, obj.token)
        sqlDecryptedUuid = ase_decrypt(obj.key1, obj.key2, data1)
        # 比对系统获取的机器码和加密的机器码是否一致
        uuid = get_system_uuid()
        return True if sqlDecryptedUuid.startswith(uuid) else False
    except Exception as err:
        logger.error(f"validate_token error: {err}")
        logger.error(''.join(traceback.format_exc()))
    

class AuthView(APIView):
    """登录认证"""
    authentication_classes = []

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING),
            'password': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['username', 'password'],
    ))
    def post(self, request, *args, **kwargs):
        ret = get_error_result("Success")
        user = request.data.get("username")
        pwd = request.data.get("password")
        remote_ip = request.META.get('HTTP_X_FORWARDED_FOR') if request.META.get(
            'HTTP_X_FORWARDED_FOR') else request.META.get("REMOTE_ADDR")
        user_info = None
        try:

            logger.info("user login: %s login , login ip %s"% (user, remote_ip))
            obj = AdminUser.objects.filter(deleted=False, username=user).first()
            if not obj or not obj.validate_password(pwd):
                logger.error("user login error: %s login fail !!!"% user)
                ret = get_error_result("LoginFailError")
                return JSONResponse(ret)
            role = Role.objects.filter(deleted=False, id=obj.role_id).first()
            if not role.enable:
                logger.error("user login error:%s account permission is disabled" % role.role)
                ret = get_error_result("AccountPermissionDisabledError")
                return JSONResponse(ret)
            if not obj.is_active:
                logger.error("user login error: %s is disabled", user)
                ret = get_error_result("AccountDisabledError")
                user_info = {
                    "id": 0,
                    "user_name": user,
                    "user_ip": remote_ip
                }
                # return JSONResponse(ret)
            else:
                ser = AdminUserSerializer(instance=obj, context={'request': request})
                ret_data = dict()
                token = make_token(user)
                old_token = cache.get(obj.id)
                cache.set(obj.id, token)
                cache.set(token, obj, 60 * 60 * 24)
                # todo 清除旧token
                # if old_token:
                #     cache.delete(old_token)
                # tokens  = cache.get("441c5b7317352ff5ce9e6a024d32e074")
                ret_data.update({"token": token})
                ret_data.update({"user": ser.data})
                ret["data"] = ret_data

                # 更新
                obj.last_login = timezone.now()
                obj.login_ip = remote_ip
                obj.save()
                user_info = {
                    "id": obj.id,
                    "user_name": user,
                    "user_ip": remote_ip
                }
        except Exception as e:
            logger.error("user login error: ", exc_info=True)
            ret = get_error_result("OtherError")

        msg = "用户：%s 在ip: %s 处登录"%(user, remote_ip)
        insert_operation_log(msg, ret["msg"], user_info)
        return JSONResponse(ret)


class AdminUsersView(APIView):
    """
    管理员列表
    """
    def get_object(self, user_id):
        try:
            user = AdminUser.objects.filter(deleted=False).get(id=user_id)
            return user
        except Exception as e:
            return None

    def post(self, request, *args, **kwargs):
        ret = get_error_result("Success")

        try:
            _data = request.data
            user_id = 1 # _data.get("user_id")
            password = _data.get("password")
            user = self.get_object(user_id)
            if not user:
                logger.error("admin user not exist: %s"% user_id)
                ret = get_error_result("AdminUserNotExist")
                return JSONResponse(ret)
            if not password:
                # ex = Exception("not input password!")
                logger.error("admin user error: not password input")
                ret = get_error_result("NotPasswordInputError")
                return JSONResponse(ret)
            else:
                if password: user.password = create_md5(password)
                user.save()
            logger.info("update admin password: %s"% ret)
            msg = "成功修改管理员密码"
            insert_operation_log(msg, ret)
            return JSONResponse(ret)
        except Exception as e:
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


class ActivateMngCmd(Enum):
    GetActivateInfo = "getActivateInfo"
    ActivateSoft = "activateSoft"


class ActivateMngView(APIView):
    """
    存储系统授权管理
    """
    @swagger_auto_schema(request_body=openapi.Schema(type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in ActivateMngCmd.__members__.values()]),
            'authIp': openapi.Schema(type=openapi.TYPE_STRING),
            'authPort': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command == "getActivateInfo":
                resp = self.get_activate_info(request)
            elif command == "activateSoft":
                resp = self.activate_soft(request)
            else:
                resp = get_error_result("MessageError")
            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("AddUserError")
            return JSONResponse(resp)

    def get_activate_info(self, request, *args, **kwargs):
        """获取存储软件是否激活"""
        try:
            resp = {}
            # 1、判断数据库中是否存有激活信息，有则读出来解密跟系统机器码比对正确，返回true
            # 2、数据库没有激活信息、或者解密信息比对不对，返回false
            obj = AuthorizationInfo.objects.first()
            if obj and validate_token(obj):
                resp['isActivated'] = True
            else:
                resp['isActivated'] = False
            return get_error_result("Success", resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
           
    def activate_soft(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            authIp = request.data.get("authIp")
            authPort = request.data.get("authPort")

            if not authIp or not authPort:
                resp = get_error_result("MessageError")
                return resp

            # 获取机器码，一般都包含了cpu的序列号
            uuid = get_system_uuid()
            if not uuid:
                logger.error('get host uuid error!!!')
                return get_error_result("OtherError")
            
            reqData = {
                'ltype': 0, # 表示永久激活，其他数值表示试用的月数
                'uuid': uuid,
            }
            resp = activate_post("/license/", reqData, authIp, authPort)
            if resp.get('code') !=0:
                logger.error('Activation failure!!!')
                resp = get_error_result("ActivationError")
                return resp
            else:
                # 激活服务返回的数据插入数据库
                values = {
                    "key1": resp['data']['key1'],
                    "key2": resp['data']['key2'],
                    "key3": resp['data']['key3'],
                    "token": resp['data']['token']
                }
                # 数据插入数据库保存
                if AuthorizationInfo.objects.count():
                    AuthorizationInfo.objects.first().delete()
                AuthorizationInfo.objects.create(**values)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
