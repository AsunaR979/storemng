import string
import uuid
import time
import hashlib
import logging
import base64
import netaddr
import socket
import struct
import netifaces
import psutil
import random
import pytz
from enum import Enum
from datetime import datetime, timedelta

from functools import wraps
from rest_framework import serializers
from django.utils.translation import ugettext_lazy as _
from rest_framework.renderers import JSONRenderer
from django.http import HttpResponse, JsonResponse
from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from rest_framework.response import Response
from collections import OrderedDict
from rest_framework.authentication import BaseAuthentication,TokenAuthentication
from .errcode import get_error_result
from rest_framework import exceptions
from rest_framework import HTTP_HEADER_ENCODING
from django.core.cache import cache
from rest_framework.permissions import BasePermission
from .constants import *
from storesys.settings import TIME_ZONE


logger = logging.getLogger(__name__)


# 自定义软删除查询基类
class SoftDeletableQuerySetMixin(object):
    """
    QuerySet for SoftDeletableModel. Instead of removing instance sets
    its ``is_deleted`` field to True.
    """

    def delete(self):
        """
        Soft delete objects from queryset (set their ``is_deleted``
        field to True)
        """
        now_time = timezone.now()
        self.update(deleted=self.id, deleted_at=now_time)


class SoftDeletableQuerySet(SoftDeletableQuerySetMixin, QuerySet):
    pass


class SoftDeletableManagerMixin(object):
    """
    Manager that limits the queryset by default to show only not deleted
    instances of model.
    """
    _queryset_class = SoftDeletableQuerySet

    def get_queryset(self):
        """
        Return queryset limited to not deleted entries.
        """
        kwargs = {'model': self.model, 'using': self._db}
        if hasattr(self, '_hints'):
            kwargs['hints'] = self._hints

        return self._queryset_class(**kwargs).filter(deleted=False)


class SoftDeletableManager(SoftDeletableManagerMixin, models.Manager):
    pass


# 自定义软删除抽象基类
class SoftDeletableModel(models.Model):
    """
    An abstract base class model with a ``is_deleted`` field that
    marks entries that are not going to be used anymore, but are
    kept in db for any reason.
    Default manager returns only not-deleted entries.
    """
    deleted = models.IntegerField(default=0)
    deleted_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        abstract = True

    objects = SoftDeletableManager()

    def delete(self, using=None, soft=True, *args, **kwargs):
        """
        Soft delete object (set its ``is_deleted`` field to True).
        Actually delete object if setting ``soft`` to False.
        """
        if soft:
            self.deleted = self.id
            self.deleted_at = timezone.now()
            self.save(using=using)
        else:
            return super(SoftDeletableModel, self).delete(using=using, *args, **kwargs)


class WebPagination(PageNumberPagination):
    page_size = 2000 # 表示每页的默认显示数量
    page_size_query_param = 'page_size' # 表示url中每页数量参数
    page_query_param = 'page' # 表示url中的页码参数
    max_page_size = 2000  # 表示每页最大显示数量，做限制使用，避免突然大量的查询数据，数据库崩溃

    def get_paginated_response(self, data, ext_dict=None):
        _resp = {"code": 0, "msg": "成功"}
        _dict = OrderedDict([
            ('count', self.page.paginator.count),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('results', data)
        ])
        if ext_dict:
            _dict.update(ext_dict)
        _resp["data"] = _dict
        # if ext_dict:
        #     _resp.update(ext_dict)
        # return JSONResponse(_resp)
        return Response(_resp)


class JSONResponse(HttpResponse):

    def __init__(self, data, **kwargs):
        _status = kwargs.get("status", status.HTTP_200_OK)
        if status.is_success(_status):
            if "code" in data:
                if data["code"] == 0:
                    _d = data.get("data", {})
                    data = {"code": 0, "msg": data.get("msg", "成功"), "data": _d}
                # else:
                #     kwargs.update({"status": status.HTTP_404_NOT_FOUND})
            else:
                data = {"code": 0, "msg": "成功", "data": data}
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)
        super(JSONResponse, self).__setitem__("Access-Control-Allow-Origin", "*")


def create_uuid():
    return str(uuid.uuid4())


def create_md5(s, salt=''):
    new_s = str(s) + salt
    m = hashlib.md5(new_s.encode())
    return m.hexdigest()


class ServerHttpClient():
    """
    服务端接口
    """


def get_authorization_header(request):
    auth = request.META.get('HTTP_AUTHORIZATION', b'')
    if isinstance(auth, type('')):
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


def param_error(error, **kwargs):
    return JsonResponse(get_error_result(error, **kwargs), status=200,
                        json_dumps_params={'ensure_ascii': False})


def datetime_to_timestamp(times):
    time_strp = time.strptime(times, "%Y-%m-%d %H:%M:%S")
    timestamp = int(time.mktime(time_strp))
    return timestamp


class CustomDateTimeField(serializers.DateTimeField):
    def to_representation(self, value):
        utc = timezone.utc
        # 先将时间值设置为UTC时区
        tz = timezone.get_default_timezone()
        # 转换时区
        local = value.replace(tzinfo=utc).astimezone(tz)
        output_format = '%Y-%m-%d %H:%M:%S'
        return local.strftime(output_format)


class DateTimeFieldMix(serializers.ModelSerializer):

    deleted_at = CustomDateTimeField(read_only=True)
    updated_at = CustomDateTimeField(read_only=True)
    created_at = CustomDateTimeField(read_only=True)


class Authentication(BaseAuthentication):
    '''认证类'''

    # def authenticate(self, request):
    #     token = request._request.GET.get("token")
    #     token_obj = models.member_token.objects.filter(token=token).first()
    #     if not token_obj:
    #         raise exceptions.AuthenticationFailed('用户认证失败')
    #     return (token_obj.user, token_obj)  # 这里返回值一次给request.user,request.auth

    # def authenticate_header(self, request):
    #     pass

    def authenticate(self, request):
        auth = get_authorization_header(request)
        # backend request, not authenticate
        if auth == b"backend":
            return "backend", b"6e85a09cca84aef8a255416707e65b1b"
        if not auth:
            raise exceptions.AuthenticationFailed("用户认证失败")
        try:
            token = auth.decode()
        except UnicodeError as e:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)
        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        # 解决循环导入问题
        from web_manage.admin.models import AdminUser, Role
        try:
            # token string:1 <==> base64 string
            _s = base64.b64decode(key[6:]).decode("utf-8")
            token, uid = _s.split(":")
            if not token or not cache.get(token):
                logger.error("token not exist")
                raise Exception("token not exist")

            cache_user = cache.get(token)
            if uid != str(cache_user.id):
                logger.error("user id is not correct")
                raise Exception("token error")
        except Exception as e:
            raise exceptions.AuthenticationFailed('auth fail.')
        try:
            _id = cache_user.id
            user = AdminUser.objects.filter(deleted=False).get(id=_id)
            if not user.is_active:
                logger.error("the account has been disabled:%s" % _id)
                raise Exception("account has disabled")
            role = Role.objects.filter(deleted=False).get(id=user.role_id)
            if not role.enable:
                logger.error("the account permission is disabled: %s" % role.role)
                raise Exception("account permission is disabled")
        except Exception as e:
            raise exceptions.PermissionDenied('No authority')
        return cache_user, token

    def authenticate_header(self, request):
        return 'Token'


class Permission(BasePermission):

    def has_permission(self, request, view):
        # print("permission .....")
        if request._request.path.endswith("/menus/"):
            return True

        if not request.user:
            return False

        return True


class FileOp(object):

    def __init__(self, file_path, open_mode=''):
        self.file_path = file_path
        self.open_mode = open_mode

    def exist_file(self):
        if not os.path.exists(self.file_path):
            return False

        ret = os.path.isfile(self.file_path)
        return ret

    def read(self):
        if self.open_mode == '':
            self.open_mode = 'r'
        with open(self.file_path, self.open_mode) as fid:
            content = fid.read()
        return content

    def write(self, content):
        if self.open_mode == '':
            self.open_mode = 'w'
        with open(self.file_path, self.open_mode) as fid:
            fid.write(content)
            fid.flush()
            os.fsync(fid.fileno())
            fid.close()

    def readlines(self):
        if self.open_mode == '':
            self.open_mode = 'r'
        with open(self.file_path, self.open_mode) as fid:
            content_lines = fid.readlines()
        return content_lines

    def write_with_endline(self, content):
        with open(self.file_path, self.open_mode) as fid:
            fid.write(content)
            fid.write('\n')
            fid.flush()
            os.fsync(fid.fileno())
            fid.close()


def errors_to_str(errors):
    s = []
    for k, v in errors.items():
        s.append("(%s:%s)"% (k, "|".join(v)))

    return " " + ",".join(s)


def is_ip_addr(ip):
    try:
        netaddr.IPAddress(ip)
        return True
    except:
        return False


def is_netmask(ip):
    ip_addr = netaddr.IPAddress(ip)
    return ip_addr.is_netmask(), ip_addr.netmask_bits()


def get_ipv4_addresses():
    '''获取本地所有IP地址V4版本'''
    ipv4_addresses = []
    # 获取所有网卡的名称
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        # 获取指定网卡的 IPv4 地址信息
        addresses = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])
        for addr_info in addresses:
            # 获取 IPv4 地址
            ipv4_address = addr_info.get('addr')
            if ipv4_address:
                ipv4_addresses.append(ipv4_address)
    return ipv4_addresses


def find_ips(start, end):
    ipstruct = struct.Struct('>I')
    start, = ipstruct.unpack(socket.inet_aton(start))
    end, = ipstruct.unpack(socket.inet_aton(end))
    return [socket.inet_ntoa(ipstruct.pack(i)) for i in range(start, end+1)]

def check_ip_on_interface(ip, nic):
    adds = []
    # 判断网卡是否存在，不存在返回False
    interfaces = netifaces.interfaces()
    if nic not in interfaces:
        return False
    ips = netifaces.ifaddresses(nic)
    for ele in ips.values():
        for ipInfo in ele:
            adds.append(ipInfo['addr'])
    if ip in adds:
        return True
    else:
        return False

def find_interface_for_ip(ip_address): 
    '''根据指定ipv4地址找到本节点对应的网卡名称，没有找到返回None'''
    for interface, info in psutil.net_if_addrs().items():  
        for addr in info:  
            if addr.family == socket.AF_INET and addr.address == ip_address:  
                return interface  
    return None  

def size_to_G(size, bit=2):
    return round(size / Gi, bit)


def size_to_M(size, bit=2):
    return round(size / Mi, bit)


def gi_to_section(size):
    return int(size * 1024 * 1024 * 2)


def bytes_to_section(_bytes):
    return int(_bytes / 512)


def timefn(fn):
    @wraps(fn)
    def measure_time(*args, **kwargs):
        t1 = time.time()
        result = fn(*args, **kwargs)
        t2 = time.time()
        logger.debug("@timefn:" + fn.__name__ + " took " + str(t2 - t1) + " seconds")
        return result
    return measure_time

def get_device_mountpoint(device):
    mountpoint = ""
    # 获取所有磁盘分区信息
    partitions = psutil.disk_partitions()
    # 查找设备 device=/dev/drbd1 的信息
    for partition in partitions:
        if partition.device == device:
            mountpoint = partition.mountpoint
            # fstype = partition.fstype
            break
    return mountpoint

# 判断str字符串是否有子字符串存在于arr字符串数组中
def is_include_in_arr(str, arr):
    for element in arr:
        if element in str:
            return True
    return False

# 据需要修改密码长度生成随机密码：只包含了字母和数字
def generate_password(length):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

#本地时间严格按照2024-04-29 19:25:31.123456
#UTC时间严格按照 2024-04-29T19:25:31.123456Z
class TimeType(Enum):
    LOCAL = 1
    UTC = 2

def translateUTCOrLoaclTimeStringToLocalTime(dateTimeString, type):

    if type == TimeType.LOCAL:
        localTime = datetime.strptime(dateTimeString, "%Y-%m-%d %H:%M:%S.%f")
        return localTime
    
    elif type == TimeType.UTC:
        # UTC时间,将界面时间还原成UTC时间
        utc_time = datetime.strptime(dateTimeString, "%Y-%m-%dT%H:%M:%S.%fZ")

        local_tz = pytz.timezone(TIME_ZONE) 

        logger.debug(f'UTC时间：{utc_time}')

        # 转换成本地时间
        local_time = utc_time.astimezone(local_tz)

        utc_offset  = local_time.utcoffset()

        hours, remainder = divmod(utc_offset.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        logger.debug(f"UTC转换成本地时间两者相差时：分：秒--> {hours}:{minutes}:{seconds}")

        local_time = utc_time + timedelta(hours=int(hours), minutes= int(minutes), seconds=int(seconds))

        return local_time
    
    else:
        return datetime.now()




if __name__ == "__main__":
    a = "1234"
    mds = create_md5(a)
    print(mds)


