from enum import Enum
import glob
import operator
import string
import logging
import base64
import copy
import subprocess
import re
import json

import psutil
from rest_framework.decorators import action
from web_manage.common import constants
from web_manage.common.utils import JSONResponse, WebPagination, Authentication, Permission, create_md5, \
    get_error_result, is_include_in_arr
from web_manage.common.log import insert_operation_log

from rest_framework.views import APIView
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.shortcuts import HttpResponse
from django.utils import timezone
import hashlib
import time
from rest_framework import status
from django.db.models import Q

from django.core.cache import cache
from django.http import Http404, HttpResponseServerError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import subprocess
import os
import traceback
from web_manage.common.cmdutils import run_cmd
from web_manage.hardware.models import AutoSnapTask, LvInfo


logger = logging.getLogger(__name__)


class VgMngCmd(Enum):
    GetPhysicalDisksAndPartions = "getPhysicalDisksAndPartions"
    GetAllPvInfo = "getAllPvInfo"
    GetSingleVgDetail = "getSingleVgDetail"
    NewVg = "newVg"
    DeleteVg = "deleteVg"
    AddDiskToVg = "addDiskToVg"
    ReduceDiskFromVg = "reduceDiskFromVg"

class VgMngView(APIView):

    """vg manage"""

    def get(self, request, *args, **kwargs):
        try:
            # 运行命令 "vgs --noheadings"
            command = "vgs --noheadings"
            output = subprocess.check_output(
                command, shell=True, encoding='utf-8')

            # 解析输出结果
            lines = output.strip().splitlines()
            volume_groups = []
            for line in lines:
                fields = line.split()
                vg_name = fields[0]
                # 跳过系统安装的默认卷组
                sys_vg_name = constants.SYS_VOLUME_GROUP
                if vg_name == sys_vg_name:
                    continue
                pv_count = fields[1]
                lv_count = fields[2]
                sn_count = fields[3]
                vg_attr = fields[4]
                vg_size = fields[5].upper()
                vg_free = fields[6].upper()
                volume_groups.append({
                    'vg_name': vg_name,
                    'pv_count': pv_count,
                    'lv_count': lv_count,
                    'sn_count': sn_count,
                    'vg_attr': vg_attr,
                    'vg_size': vg_size,
                    'vg_free': vg_free,
                })

            return JSONResponse(volume_groups)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_single_vg_detail(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            vg_name = request.data.get('vgname')
            if vg_name:
                cmd = 'vgdisplay {} --noheadings --columns --separator ,  \
                    -o vg_name,pv_count,lv_count,vg_fmt,vg_attr,vg_size,vg_free,vg_uuid'.format(
                    vg_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'not found' in output:
                        logger.error("Volume group not found!!!")
                        resp = get_error_result("VgNotFound")
                    else:
                        logger.error("Failed to get volume group details!!!")
                        resp = get_error_result("GetSinVgDetailError")
            else:
                resp = get_error_result("MessageError")

            # 解析输出结果
            line = output.strip().splitlines()[0]
            volume_groups = {}
            fields = line.split(",")
            volume_groups["vg_name"] = fields[0]
            volume_groups["pv_count"] = fields[1]
            volume_groups["lv_count"] = fields[2]
            volume_groups["vg_fmt"]= fields[3]
            volume_groups["vg_attr"] = fields[4]
            volume_groups["vg_size"] = fields[5].upper()
            volume_groups["vg_free"] = fields[6].upper()

            # 获取卷组里所有物理卷详情
            command = "pvs --noheadings"
            output = subprocess.check_output(
                command, shell=True, encoding='utf-8')

            # 解析输出结果
            lines = output.strip().splitlines()
            physical_volumes = []
            for line in lines:
                fields = line.split()
                pv_name = fields[0]
                if len(fields) == 6:
                    if vg_name != fields[1].strip():
                        continue
                    pv_fmt = fields[2]
                    pv_attr = fields[3]
                    pv_size = fields[4]
                    pv_free = fields[5]
                physical_volumes.append({
                    'pv_name': pv_name,
                    'pv_fmt': pv_fmt,
                    'pv_attr': pv_attr,
                    'pv_size': pv_size.upper(),
                    'pv_free': pv_free.upper(),
                })
            volume_groups["physical_volumes"] = physical_volumes

            return volume_groups
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def get_physical_disks(self, request, args, kwargs):
        '''
        获取所有的未被用于物理卷的盘
        '''
        try:
            physical_disks = []
            # 执行lsblk命令，获取磁盘和分区的信息
            lslbkOutput = subprocess.check_output(
                ['lsblk', '-o', 'PATH,TYPE,SIZE,PKNAME,MOUNTPOINT'])
            
            # 获取所有的物理卷
            command = "pvs --noheadings"
            (status, output) = run_cmd(command)
            lines = output.strip().splitlines()
            pvNames = []
            for line in lines:
                fields = line.split()
                pvNames.append(fields[0].strip())
            
            #获取所有用于创建raid的盘
            filename = '/etc/mdadm.conf'  
            raid_arrays = []
            with open(filename, 'r') as file:  
                for line in file:  
                    if 'devices=/' not in line:
                        continue
                    devices_str = line.split('devices=')[1].split(',')
                    for disk in devices_str:
                        if not disk:
                            continue
                        raid_arrays.append(disk.strip())

            # 解析lsblk命令的输出
            lines = lslbkOutput.decode().split('\n')
            for line in lines[1:]:
                if line:
                    # 提取磁盘和分区的信息
                    # 使用正则表达式以空白字符为分隔符分割字符串
                    parts = re.split(r'\s+', line.strip())

                    kname = parts[0]  # 设备名称
                    dev_type = parts[1]  # 设备类型，"disk"表示磁盘，"part"表示分区
                    size = parts[2] if len(parts) > 2 else None  # 大小
                    parent_disk = parts[3] if len(parts) > 3 else None  # 父磁盘
                    mount_point = parts[4] if len(parts) > 4 else None  # 挂载点

                    # 过滤掉虚拟设备，只获取物理磁盘和分区 , 去掉了分区：, 'part'
                    if dev_type in ['disk'] or 'raid' in dev_type:
                        # 过滤drbd盘
                        if "/dev/drbd" in kname:
                            continue
                        # 过滤掉系统盘和分区，不显示给用户使用
                        sys_device_path = constants.SYS_DEVICE_PATH
                        if sys_device_path in kname:
                            continue

                        #判断是否已作为raid盘
                        if kname in raid_arrays:
                            continue

                        # 如果是软raid创建的盘，做一个映射下发给前端
                        if "/dev/md" in kname:
                            print(1)

                        # 过滤掉已经创建过物理卷的
                        if kname in pvNames:
                            continue

                        disk_info = {
                            'kname': kname,
                            'type': dev_type,
                            'size': size.upper(),
                            'mount_point': mount_point,
                            'parent_disk': parent_disk
                        }
                        if any(disk['kname'] == disk_info['kname'] for disk in physical_disks): 
                            continue
                        physical_disks.append(disk_info)

            return get_error_result(data=physical_disks)
        except Exception as e:
            logger.error("call get_physical_disks %s error: " % e)
            logger.error(''.join(traceback.format_exc()))
            return get_error_result("OtherError")

    def get_all_pv_info(self, request, args, kwargs):
        try:
            # 运行命令 "pvs --noheadings"
            command = "pvs --noheadings"
            output = subprocess.check_output(
                command, shell=True, encoding='utf-8')

            # 解析输出结果
            lines = output.strip().splitlines()
            physical_volumes = []
            for line in lines:
                fields = line.split()
                pv_name = fields[0]
                if len(fields) == 6:
                    vg_name = fields[1]
                    # 跳过系统安装的默认卷组
                    sys_vg_name = constants.SYS_VOLUME_GROUP
                    if vg_name == sys_vg_name:
                        continue
                    pv_fmt = fields[2]
                    pv_attr = fields[3]
                    pv_size = fields[4]
                    pv_free = fields[5]
                else:
                    vg_name = 'None'
                    pv_fmt = fields[1]
                    pv_attr = fields[2]
                    pv_size = fields[3]
                    pv_free = fields[4]
                physical_volumes.append({
                    'pv_name': pv_name,
                    'vg_name': vg_name,
                    'pv_fmt': pv_fmt,
                    'pv_attr': pv_attr,
                    'pv_size': pv_size.upper(),
                    'pv_free': pv_free.upper(),
                })

            return get_error_result(data=physical_volumes)
        except Exception as e:
            logger.error("get lvm pvs error: %s", e)
            logger.error(''.join(traceback.format_exc()))
            return get_error_result("OtherError")

    def disk_to_pv(self, disk):
        try:
            # 判断物理卷是否已经被添加过
            command = "pvs --noheadings"
            (status, output) = run_cmd(command)
            lines = output.strip().splitlines()
            pvNames = []
            for line in lines:
                fields = line.split()
                pvNames.append(fields[0].strip())
            if disk in pvNames:
                logger.warn(f"{disk} already exists on system!")
                resp = get_error_result("PvIsExistsOnSystem")
                return resp
            
            # Todo: 过滤掉已经创建过软Raid的物理盘或分区 

            # 先格式化磁盘或分区
            formatCmd = 'mkfs.ext4 -F {}'.format(disk)
            (status, formatoutput) = run_cmd(formatCmd)
            if status != 0:
                if status == 1:
                    logger.error("Device is already mounted or in use!!!")
                    resp = get_error_result("LvIsMountedInUse")
                else:
                    logger.error("Format failed!!!")
                    resp = get_error_result("FormatError")
                return resp
            # 再将格式化后的磁盘或分区创建为物理卷
            addPvCmd = 'pvcreate -f {}'.format(disk)
            (status, addPvoutput) = run_cmd(addPvCmd)
            if status != 0:
                logger.error("Failed to add physical volume!!!")
                resp = get_error_result("AddPvError")
            return get_error_result("Success")
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def pv_to_disk(self, pv_name):
        try:
            resp = get_error_result("Success")

            cmd = 'pvremove {}'.format(pv_name)
            (status, output) = run_cmd(cmd)
            if status != 0:
                if 'please use vgreduce first' in output:
                    logger.error("Please remove the physical volume from the volume group first!!!")
                    resp = get_error_result("UseVgreduceFirst")
                else:
                    logger.error("Failed to delete physical volume!!!")
                    resp = get_error_result("DeletePvError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def new_vg(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            vg_name = request.data.get('vgname')
            disk_list = request.data.get('disk_list')

            # 判断数据有效性
            if not vg_name or not disk_list:
                resp = get_error_result("MessageError")
                return resp                
            # 判断系统设备目录是否存在有同名的设备名称
            deviceNames = os.listdir('/dev/')
            if vg_name in deviceNames:
                resp = get_error_result("DeviceNameAlreadyExists")
                return resp
            
            # 物理盘转物理卷
            for disk in disk_list:
                resp = self.disk_to_pv(disk)
                if resp.get('code') != 0:
                    return resp

            # 使用多个物理卷创建卷组
            cmd = 'vgcreate {} {}'.format(vg_name, ' '.join(disk_list))
            (status, output) = run_cmd(cmd)
            if status != 0:
                # 判断output的内容
                if 'already exists in filesystem' in output:
                    logger.error("Volume group already exists!!!")
                    resp = get_error_result("VgAlreadyExists")
                elif 'is already in volume group' in output:
                    logger.error("Physical volume already in use!!!")
                    resp = get_error_result("PvHasBeenUsed")
                elif 'not found' in output:
                    logger.error("Physical volume not found!!!")
                    resp = get_error_result("PvNotFound")
                else:
                    logger.error("Failed to add volume group!!!")
                    resp = get_error_result("AddVgError")
                # 创建卷组失败，需要把物理卷进行回滚
                for disk in disk_list:
                    self.pv_to_disk(disk)
                
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def delete_vg(self, request, args, kwargs):
        try:
            vg_name = request.data.get('vgname')
            if not vg_name:
                resp = get_error_result("MessageError")
                return resp

            # 获取该卷组下的所有物理卷
            pvNameList = []
            command = "pvs --noheadings"
            output = subprocess.check_output(
                command, shell=True, encoding='utf-8')
            lines = output.strip().splitlines()
            for line in lines:
                fields = line.split()
                pvName = fields[0].strip()
                vgName = fields[1].strip()
                if vgName == vg_name:
                    pvNameList.append(pvName)

            # 删除卷组
            cmd = 'vgremove {}'.format(vg_name)
            (status, output) = run_cmd(cmd)
            if status != 0:
                if 'containing' in output:
                    logger.error("Logical volumes exist in the volume group!!!")
                    resp = get_error_result("VgContainLv")
                    return resp
                else:
                    logger.error("Failed to delete volume group!!!")
                    resp = get_error_result("DeleteVgError")
                    return resp
            else:
                # 把卷组下的所有物理卷转为物理盘
                for pvName in pvNameList:
                    resp = self.pv_to_disk(pvName)
                    if resp.get('code') != 0:
                        return resp
            resp = get_error_result("Success")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_disk_to_vg(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            disk_list = request.data.get('disk_list')
            vg_name = request.data.get('vgname')
            if disk_list and vg_name:
                # 先把磁盘转为物理卷
                for disk in disk_list:
                    resp = self.disk_to_pv(disk)
                    if resp.get('code') != 0:
                        return resp
                # 物理卷再添加到卷组中
                cmd = 'vgextend {} {}'.format(vg_name, ' '.join(disk_list))
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'is already in volume group' in output:
                        logger.error("The physical volume is already in volume group!!!")
                        resp = get_error_result("PvAlreadyInVg")
                    else:
                        logger.error("Failed to join the volume group!!!")
                        resp = get_error_result("AddPvToVgError")
                    # 扩容卷组失败，需要把物理卷进行回滚
                    for disk in disk_list:
                        self.pv_to_disk(disk)
            else:
                resp = get_error_result("MessageError")        
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def reduce_disk_from_vg(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            disk = request.data.get('disk')
            vg_name = request.data.get('vgname')
            if disk and vg_name:
                cmd = 'vgreduce {} {}'.format(vg_name, disk)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    # 判断output的内容
                    if 'still in use' in output:
                        logger.error("The physical volume is currently in use!!!")
                        resp = get_error_result("PvInUse")
                    elif 'remove final physical volume' in output:
                        logger.error("This is the last physical volume in the volume group, please delete the corresponding volume group first!!!")
                        resp = get_error_result("FinalPvFromVg")
                    elif 'Failed to find physical volume' in output:
                        logger.error("The physical volume is not part of any volume group!!!")
                        resp = get_error_result("PvNotInVG")
                    else:
                        logger.error("Failed to remove from the volume group!!!")
                        resp = get_error_result("ReducePvFromVgError")
                else:
                    # 把物理卷转为物理盘
                    resp = self.pv_to_disk(disk)
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp
        
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in VgMngCmd.__members__.values()]),
            'pvname': openapi.Schema(type=openapi.TYPE_STRING),
            'vgname': openapi.Schema(type=openapi.TYPE_STRING),
            'disk': openapi.Schema(type=openapi.TYPE_STRING),
            'disk_list': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='磁盘路径列表' ),
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
            if command not in ["getSingleVgDetail", "getPhysicalDisksAndPartions", "getAllPvInfo"]:
                insert_operation_log(msg, ret["msg"], user_info)
            if command == "getPhysicalDisksAndPartions":
                ret = self.get_physical_disks(request, args, kwargs)
            elif command == "getAllPvInfo":
                ret = self.get_all_pv_info(request, args, kwargs)
            elif command == "newVg":
                ret = self.new_vg(request, args, kwargs)
            elif command == "deleteVg":
                ret = self.delete_vg(request, args, kwargs)
            elif command == "getSingleVgDetail":
                ret = self.get_single_vg_detail(request, args, kwargs)
            elif command == "addDiskToVg":
                ret = self.add_disk_to_vg(request, args, kwargs)
            elif command == "reduceDiskFromVg":
                ret = self.reduce_disk_from_vg(request, args, kwargs)                
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)


class PvMngView(APIView):

    """pv manage"""

    def get(self, request, *args, **kwargs):
        try:
            # 运行命令 "pvs --noheadings"
            command = "pvs --noheadings"
            output = subprocess.check_output(
                command, shell=True, encoding='utf-8')

            # 解析输出结果
            lines = output.strip().splitlines()
            physical_volumes = []
            for line in lines:
                fields = line.split()
                pv_name = fields[0]
                if len(fields) == 6:
                    vg_name = fields[1]
                    # 跳过系统安装的默认卷组
                    sys_vg_name = constants.SYS_VOLUME_GROUP
                    if vg_name == sys_vg_name:
                        continue
                    pv_fmt = fields[2]
                    pv_attr = fields[3]
                    pv_size = fields[4]
                    pv_free = fields[5]
                else:
                    vg_name = 'None'
                    pv_fmt = fields[1]
                    pv_attr = fields[2]
                    pv_size = fields[3]
                    pv_free = fields[4]
                physical_volumes.append({
                    'pv_name': pv_name,
                    'vg_name': vg_name,
                    'pv_fmt': pv_fmt,
                    'pv_attr': pv_attr,
                    'pv_size': pv_size.upper(),
                    'pv_free': pv_free.upper(),
                })

            return JSONResponse(physical_volumes)
        except Exception as e:
            logger.error("get lvm pvs error: %s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def get_physical_disks(self, request, args, kwargs):
        try:
            physical_disks = []
            # 执行lsblk命令，获取磁盘和分区的信息
            output = subprocess.check_output(
                ['lsblk', '-o', 'PATH,TYPE,SIZE,PKNAME,MOUNTPOINT'])

            # 解析lsblk命令的输出
            lines = output.decode().split('\n')
            for line in lines[1:]:
                if line:
                    # 提取磁盘和分区的信息
                    # 使用正则表达式以空白字符为分隔符分割字符串
                    parts = re.split(r'\s+', line.strip())

                    kname = parts[0]  # 设备名称
                    dev_type = parts[1]  # 设备类型，"disk"表示磁盘，"part"表示分区
                    size = parts[2] if len(parts) > 2 else None  # 大小
                    parent_disk = parts[3] if len(parts) > 3 else None  # 父磁盘
                    mount_point = parts[4] if len(parts) > 4 else None  # 挂载点

                    # 过滤掉虚拟设备，只获取物理磁盘和分区 , 去掉了分区：, 'part'
                    if dev_type in ['disk']:
                        # 过滤drbd盘
                        if "/dev/drbd" in kname:
                            continue
                        # 过滤掉系统盘和分区，不显示给用户使用
                        sys_device_path = constants.SYS_DEVICE_PATH
                        if sys_device_path in kname:
                            continue
                        # 如果是软raid创建的盘，做一个映射下发给前端
                        if "/dev/md/" in kname:
                            kname = os.path.realpath(kname)
                        disk_info = {
                            'kname': kname,
                            'type': dev_type,
                            'size': size.upper(),
                            'mount_point': mount_point,
                            'parent_disk': parent_disk
                        }
                        physical_disks.append(disk_info)

            return physical_disks
        except Exception as e:
            logger.error("call get_physical_disks %s error: " % e)
            logger.error(''.join(traceback.format_exc()))
            return get_error_result("OtherError")

    def get_single_pv_detail(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            pv_name = request.data.get('pvname')
            if pv_name:
                cmd = 'pvdisplay {} --noheadings --columns --separator ,  \
                    -o pv_name,vg_name,pv_fmt,pv_size,pv_free,pv_attr'.format(
                    pv_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'Failed to find physical volume' in output:
                        logger.error("Failed to find physical volume!!!")
                        resp = get_error_result("FailedToFindPv")
                    else:
                        logger.error("Failed to get physical volume details!!!")
                        resp = get_error_result("GetSinPvDetailError")
            else:
                resp = get_error_result("MessageError")
            # 解析输出结果
            line = output.strip().splitlines()[0]
            volume_groups = {}
            fields = line.split(",")
            volume_groups["pv_name"] = fields[0]
            volume_groups["vg_name"] = fields[1]
            volume_groups["pv_fmt"] = fields[2]
            volume_groups["pv_size"]= fields[3].upper()
            volume_groups["pv_free"] = fields[4].upper()
            volume_groups["pv_attr"] = fields[5]
            return volume_groups
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_physical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            pv_name = request.data.get('pvname')
            #pv_name = " ".join(pv_name) # 使用空格作为连接符将列表中的元素连接成一个字符串

            # 判断数据有效性
            if not pv_name:
                resp = get_error_result("MessageError")
                return resp
            
            # 判断物理卷是否已经被添加过
            command = "pvs --noheadings"
            (status, output) = run_cmd(command)
            lines = output.strip().splitlines()
            pvNames = []
            for line in lines:
                fields = line.split()
                pvNames.append(fields[0].strip())
            if pv_name in pvNames:
                logger.warn(f"{pv_name} already exists on system!")
                resp = get_error_result("PvIsExistsOnSystem")
                return resp
            
            # Todo: 过滤掉已经创建过软Raid的物理盘或分区 

            # 先格式化磁盘或分区
            formatCmd = 'mkfs.ext4 -F {}'.format(pv_name)
            (status, formatoutput) = run_cmd(formatCmd)
            if status != 0:
                if status == 1:
                    logger.error("Device is already mounted or in use!!!")
                    resp = get_error_result("LvIsMountedInUse")
                else:
                    logger.error("Format failed!!!")
                    resp = get_error_result("FormatError")
                return resp
            # 再将格式化后的磁盘或分区创建为物理卷
            addPvCmd = 'pvcreate -f {}'.format(pv_name)
            (status, addPvoutput) = run_cmd(addPvCmd)
            if status != 0:
                '''
                if 'signature detected' in output:
                    resp = get_error_result("DeviceMayHaveData")
                elif 'Mounted filesystem' in output:
                    resp = get_error_result("MountedFilesystem")
                elif 'of volume group' in output:
                    resp = get_error_result("DeviceIsPvInVg")
                elif 'excluded by a filter' in output:
                    resp = get_error_result("DeviceCannotBePv")
                else:
                    resp = get_error_result("AddPvError")
                '''
                logger.error("Failed to add physical volume!!!")
                resp = get_error_result("AddPvError")
            # 正常返回
            resp = get_error_result("Success")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def drop_physical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            pv_name = request.data.get('pvname')
            if pv_name:
                cmd = 'pvremove {}'.format(pv_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'please use vgreduce first' in output:
                        logger.error("Please remove the physical volume from the volume group first!!!")
                        resp = get_error_result("UseVgreduceFirst")
                    else:
                        logger.error("Failed to delete physical volume!!!")
                        resp = get_error_result("DeletePvError")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def add_pv_to_vg(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            pv_name = request.data.get('pvname')
            vg_name = request.data.get('vgname')
            if pv_name:
                cmd = 'vgextend {} {}'.format(vg_name, pv_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'is already in volume group' in output:
                        logger.error("The physical volume is already in volume group!!!")
                        resp = get_error_result("PvAlreadyInVg")
                    else:
                        logger.error("Failed to join the volume group!!!")
                        resp = get_error_result("AddPvToVgError")
            else:
                resp = get_error_result("MessageError")        
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def reduce_pv_from_vg(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            pv_name = request.data.get('pvname')
            vg_name = request.data.get('vgname')
            if pv_name:
                cmd = 'vgreduce {} {}'.format(vg_name, pv_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    # 判断output的内容
                    if 'still in use' in output:
                        logger.error("The physical volume is currently in use!!!")
                        resp = get_error_result("PvInUse")
                    elif 'remove final physical volume' in output:
                        logger.error("This is the last physical volume in the volume group, please delete the corresponding volume group first!!!")
                        resp = get_error_result("FinalPvFromVg")
                    elif 'Failed to find physical volume' in output:
                        logger.error("The physical volume is not part of any volume group!!!")
                        resp = get_error_result("PvNotInVG")
                    else:
                        logger.error("Failed to remove from the volume group!!!")
                        resp = get_error_result("ReducePvFromVgError")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING),
            'pvname': openapi.Schema(type=openapi.TYPE_STRING),
            'vgname': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command not in ["getPhysicalDisksAndPartions", "getSinglePvDetail"]:
                insert_operation_log(msg, ret["msg"], user_info)
            if command == "getPhysicalDisksAndPartions":
                ret = self.get_physical_disks(request, args, kwargs)
            elif command == "addPhysicalVolume":
                ret = self.add_physical_volume(request, args, kwargs)
            elif command == "dropPhysicalVolume":
                ret = self.drop_physical_volume(request, args, kwargs)
            elif command == "addPvToVg":
                ret = self.add_pv_to_vg(request, args, kwargs)
            elif command == "reducePvFromVg":
                ret = self.reduce_pv_from_vg(request, args, kwargs)
            elif command == "getSinglePvDetail":
                ret = self.get_single_pv_detail(request, args, kwargs)
            elif command == "getPhysicalDisksAndPartions":
                ret = self.get_physical_disks(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)



class LvMngCmd(Enum):
    CreateLv = "createLv"
    DeleteLv = "deleteLv"
    ExtendLv = "extendLv"
    BackupLv = "backupLv"
    CreateLvSnap = "createLvSnap"
    RestoreLvSnap = "restoreLvSnap"
    CopySnap = "copySnap"
    GetSingleLvDetail = "getSingleLvDetail"
    FormatLv = "formatLv"
    MountLv = "mountLv"
    UmountLv = "umountLv"


class LvMngView(APIView):

    """lv manage"""

    '''
    创建
    lvcreate -n lvname -L 64M -W n vg1
    扩容
    lvextend -L +100m /dev/vg1/lvname
    缩容
    lvreduce -L -100m /dev/vg1/lvname
    删除
    lvremove /dev/vg1/lvname
    备份
    lvcreate  -L 20m  --name lv1_copy01 /dev/vg1/lvname1
    快照
    lvcreate --snapshot  -L 20m  --name snap1 /dev/vg1/lvname1
    快照还原
    lvconvert --merge /dev/vgl/snap1
    '''
     
    def get(self, request, *args, **kwargs):
        try:
            # 执行 lsblk 命令并获取输出
            command_output = subprocess.run(['lsblk', '--output', 'name,fstype,mountpoint', '--noheadings', '-J'], capture_output=True, text=True)
            
            # 检查是否有错误
            lvBlkInfo = []
            if command_output.returncode == 0:
                # 解析 JSON 格式的输出
                lsblk_output = json.loads(command_output.stdout)
                filtered_elements = self.find_lvm2_member(lsblk_output['blockdevices'])
                filtered_elements = [element for element in filtered_elements if element.get('children')]
                children_list = [element['children'] for element in filtered_elements]
                for sublist in children_list:
                    for child in sublist:
                        lvBlkInfo.append(child)

            # 获取逻辑卷信息
            command_lvs = "lvs --noheadings --separator=',' -o lv_name,vg_name,lv_attr,lv_size,lv_path,origin,lv_time"
            output_lvs = subprocess.check_output(command_lvs, shell=True, encoding='utf-8')

            # 解析输出结果
            lines = output_lvs.strip().splitlines()
            # 构建逻辑卷信息列表
            logical_volumes = []
            for line in lines:
                #fields = line.split(",")
                fields = [item.strip() for item in line.split(",")] # 去除元素中的首尾空格
                lv_name = fields[0]
                vg_name = fields[1]
                # 跳过系统安装的默认卷组
                sys_vg_name = constants.SYS_VOLUME_GROUP
                if vg_name == sys_vg_name:
                    continue
                lv_attr = fields[2]
                lv_size = fields[3].upper()
                lv_path = fields[4]
                origin = fields[5]
                create_time = " ".join(fields[6].split()[:2]) if len(fields) > 5 else ""
                is_drbd = False
                lv_fstype = ""
                lv_mountdir = ""

                # 根据输入逻辑卷信息查找对应的信息：挂载点，文件类型，是否为drbd虚拟盘
                given_name = vg_name + '-' + lv_name
                #matching_elements = [element for element in lvBlkInfo if element['name'] == given_name]
                matching_elements = self.find_lv_element(lvBlkInfo, given_name)
                found_element = None
                if matching_elements:
                    found_element = matching_elements[0]
                if found_element:
                    lv_fstype = found_element["fstype"]
                    lv_mountdir = found_element["mountpoint"]
                    if found_element["fstype"] == "drbd":
                        is_drbd = True
                        lv_fstype = ""

                # 如果lv_fstype还是空的，再使用blkid命令查询下文件类型：san盘的文件类型系统lsblk获取不到
                if not lv_fstype:
                    lv_fstype = self.get_fstype_info(f"/dev/{vg_name}/{lv_name}")
                    lv_fstype = "" if lv_fstype == "drbd" else lv_fstype

                # 获取逻辑卷的存储类型，从数据库中获取
                storeType = ""
                if LvInfo.objects.count():
                    if origin == '':
                        lvInfo = LvInfo.objects.get(lvname=lv_name, vgname=vg_name)
                        storeType = lvInfo.store_type
                    else:
                        # 快照卷，查询需要使用源卷信息去查询
                        lvInfo = LvInfo.objects.get(lvname=origin, vgname=vg_name)
                        storeType = lvInfo.store_type

                logical_volumes.append({
                    'lv_name': lv_name,
                    'vg_name': vg_name,
                    'lv_attr': lv_attr,
                    'lv_size': lv_size,
                    'lv_path': lv_path,
                    'origin': origin,
                    'is_drbd': is_drbd,
                    'create_time': create_time,
                    'lv_fstype': lv_fstype,
                    'lv_mountdir': "" if lv_mountdir is None else lv_mountdir,
                    'store_type': storeType,
                    # 'data_percent': data_percent,
                    # 'meta_percent': meta_percent,
                    # 'move': move,
                    # 'log': log,
                    # 'copy_sync': copy_sync,
                    # 'convert': convert,
                })

            # 以JSON格式返回逻辑卷信息列表
            return JSONResponse(logical_volumes)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("get lvm lvs error: %s", e)
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def get_fstype_info(self, device):
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
        return fstype
    
    # 递归查询嵌套在 children 字段中的元素
    def find_lv_element(self, lvBlkInfo, given_name):
        for element in lvBlkInfo:
            if element['name'] == given_name:
                return [element]
            elif 'children' in element:
                matched_elements = self.find_lv_element(element['children'], given_name)
                if matched_elements:
                    return matched_elements
        return None

    # 递归查询到所有LVM2_member的device：包括普通分区和磁盘，还有逻辑卷
    def find_lvm2_member(self, devices):
        lvm2_member_list = []
    
        for device in devices:
            if device.get('fstype') == 'LVM2_member':
                lvm2_member_list.append(device)
    
            children = device.get('children', [])
            lvm2_member_list.extend(self.find_lvm2_member(children))
        return lvm2_member_list    

    def get_single_lv_detail(self, request, *args, **kwargs):
        try:
            resp = get_error_result("Success")
            lv_path = request.data.get('lvpath')
            if lv_path:
                cmd = 'lvdisplay {} --noheadings --columns --separator ,  \
                    -o lv_name,lv_path,vg_name,lv_attr,lv_size,lv_active,origin,origin_size,origin_uuid,lv_uuid'.format(
                    lv_path)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'Failed to find logical volume' in output:
                        logger.error("Failed to find logical volume!!!")
                        resp = get_error_result("FailedToFindLv")
                    else:
                        logger.error("Failed to get the details of the logical volume!!!")
                        resp = get_error_result("GetSinLvDetailError")
            else:
                resp = get_error_result("MessageError")
            # 解析输出结果
            line = output.strip().splitlines()[0]
            volume_groups = {}
            fields = line.split(",")
            volume_groups["lv_name"] = fields[0]
            volume_groups["lv_path"] = fields[1]
            volume_groups["vg_name"] = fields[2]
            volume_groups["lv_attr"]= fields[3]
            volume_groups["lv_size"] = fields[4].upper()
            volume_groups["lv_active"] = fields[5]
            volume_groups["origin"] = fields[6]
            return volume_groups
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in LvMngCmd.__members__.values()]),
            'lvname': openapi.Schema(type=openapi.TYPE_STRING),
            'lvpath': openapi.Schema(type=openapi.TYPE_STRING),
            'storetype': openapi.Schema(type=openapi.TYPE_STRING),
            'vgname': openapi.Schema(type=openapi.TYPE_STRING),
            'size': openapi.Schema(type=openapi.TYPE_STRING),
            'snap_name': openapi.Schema(type=openapi.TYPE_STRING),
            'snap_path': openapi.Schema(type=openapi.TYPE_STRING),
            'args': openapi.Schema(type=openapi.TYPE_STRING),
            'filesys_type': openapi.Schema(type=openapi.TYPE_STRING),
            'mount_dir': openapi.Schema(type=openapi.TYPE_STRING),
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
            if command not in ["getSingleLvDetail", "getAllLvDetail"]:
                insert_operation_log(msg, ret["msg"], user_info)            
            if command == "createLv":
                ret = self.create_logical_volume(request, args, kwargs)
            elif command == "deleteLv":
                ret = self.delete_logical_volume(request, args, kwargs)
            elif command == "getSingleLvDetail":
                ret = self.get_single_lv_detail(request, args, kwargs)         
            elif command == "getAllLvDetail":
                return self.get(request, args, kwargs)
            elif command == "extendLv":
                ret = self.extend_logical_volume(request, args, kwargs)
            elif command == "backupLv":
                ret = self.backup_logical_volume(request, args, kwargs)
            elif command == "createLvSnap":
                ret = self.create_logical_volume_snap(request, args, kwargs)
            elif command == "restoreLvSnap":
                ret = self.restore_logical_volume_snap(request, args, kwargs)
            elif command == "copySnap":
                ret = self.copy_snap(request, args, kwargs)
            elif command == "formatLv":
                ret = self.format_logical_volume(request, args, kwargs)
            elif command == "mountLv":
                ret = self.mount_logical_volume(request, args, kwargs)
            elif command == "umountLv":
                ret = self.umount_logical_volume(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            logger.error("user execute %s error: " % command)
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    # 创建逻辑卷
    def create_logical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            lv_name = request.data.get('lvname')
            # 存储类型：nas、fan、other
            storeType = request.data.get('storetype')
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = request.data.get('size')
            vg_name = request.data.get('vgname')
            if lv_name:
                cmd = 'lvcreate -y -n {} -L {} -W n {}'.format(lv_name, size, vg_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'already exists in volume group' in output:
                        logger.error("The logical volume already exists in the volume group!!!")
                        resp = get_error_result("LvExistsInVg")
                    elif 'has insufficient free space' in output:
                        logger.error("The volume group has insufficient available space!!!")
                        resp = get_error_result("VgNoFreeSpace")
                    else:
                        logger.error("Failed to create the logical volume!!!")
                        resp = get_error_result("CreateLvError")
                else:
                    if storeType == 'nas':
                        lvpath = '/dev/{}/{}'.format(vg_name,lv_name)
                        mount_dir = '/data/{}/{}'.format(vg_name,lv_name)
                        cmd = 'mkfs.ext4 {} -F'.format(lvpath)
                        (status, output) = run_cmd(cmd)
                        if status != 0:
                            if is_include_in_arr(output, ['is mounted', 'contains a mounted filesystem', '已经挂载', '已挂载']):
                                logger.error("Device is already mounted!!!")
                                resp = get_error_result("DeviceIsMounted")
                            elif is_include_in_arr(output, ['in use by the system', 'Device or resource busy', '正被系统使用', '设备或资源忙']):
                                logger.error("Device is in use!!!")
                                resp = get_error_result("DeviceIsInUse")
                            elif is_include_in_arr(output, ['too small']):
                                logger.error("Superblock size of the file system to be formatted is too small!!!")
                                resp = get_error_result("SuperblockTooSmall")
                            else:
                                logger.error("Format failed!!!")
                                resp = get_error_result("FormatError")

                        if mount_dir and not os.path.exists(mount_dir):
                            os.makedirs(mount_dir)
                        cmd = 'mount {} {}'.format(lvpath, mount_dir)
                        (status, output) = run_cmd(cmd)
                        if status != 0:
                            # 判断output的内容
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

                    # 数据库记录存储类型
                    values = {
                        "lvname": lv_name,
                        "vgname": vg_name,
                        "store_type": storeType
                    }
                    # 数据插入数据库保存
                    LvInfo.objects.create(**values)
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 格式化逻辑卷
    def format_logical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            filesys_type = request.data.get('filesys_type')
            lv_path = request.data.get('lvpath')
            lv_name = request.data.get('lvname')

            # SAN类型的卷，禁止做格式化操作
            lvInfo = LvInfo.objects.filter(lvname=lv_name).first()
            if lvInfo and lvInfo.store_type == 'san':
                resp = get_error_result("SanLvCanNotFormat")
                return resp

            # 根据文件系统类型选择格式化参数
            if filesys_type in ['ext2', 'ext3', 'ext4']:
                force_parameter = '-F'
            elif filesys_type in ['xfs', 'btrfs']:
                force_parameter = '-f'
            elif filesys_type in ['ntfs', 'vfat', 'minix']:
                force_parameter = ''
            else:
                force_parameter = ''

            if filesys_type:
                cmd = 'mkfs.{} {} {}'.format(filesys_type, lv_path, force_parameter)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if is_include_in_arr(output, ['is mounted', 'contains a mounted filesystem', '已经挂载', '已挂载']):
                        logger.error("Device is already mounted!!!")
                        resp = get_error_result("DeviceIsMounted")
                    elif is_include_in_arr(output, ['in use by the system', 'Device or resource busy', '正被系统使用', '设备或资源忙']):
                        logger.error("Device is in use!!!")
                        resp = get_error_result("DeviceIsInUse")
                    elif is_include_in_arr(output, ['too small']):
                        logger.error("Superblock size of the file system to be formatted is too small!!!")
                        resp = get_error_result("SuperblockTooSmall")
                    else:
                        logger.error("Format failed!!!")
                        resp = get_error_result("FormatError")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 挂载逻辑卷
    def mount_logical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            lv_path = request.data.get('lvpath')
            mount_dir = request.data.get('mount_dir')
           
            if mount_dir:
                # 如果是drbd的虚拟盘挂载，特殊处理双机资源的故障转移
                resName = request.data.get('lvName')
                # 查找双机资源drbd资源的切换脚本进行修改
                resAlterScript = "/etc/keepalived/to_master/drbd_%s.sh" % resName
                if os.path.exists(resAlterScript):
                    # 对mount这行文本执行替换操作
                    replaceText = "mount %s %s" % (lv_path, mount_dir)
                    replaceText = replaceText.replace("/", "\/")
                    sedCmd = "sed -i '/^#*.*mount/s/.*/%s/' %s" % (replaceText, resAlterScript)
                    (status, output) = run_cmd(sedCmd)
                    if status != 0:
                        logger.error("Failed to execute sed command!!!")
                        resp = get_error_result("ExecuteSedCmdError")
                # 判断路径是否存在，不存在则创建
                if mount_dir and not os.path.exists(mount_dir):
                    os.makedirs(mount_dir)
                cmd = 'mount {} {}'.format(lv_path, mount_dir)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    # 判断output的内容
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
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 卸载逻辑卷
    def umount_logical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            lv_path = request.data.get('lvpath')
            mount_dir = request.data.get('mountDir')
            if lv_path:
                # 如果是drbd的虚拟盘挂载，特殊处理双机资源的故障转移
                resName = request.data.get('lvName')
                # 查找双机资源drbd资源的切换脚本进行修改
                resAlterScript = "/etc/keepalived/to_master/drbd_%s.sh" % resName
                if os.path.exists(resAlterScript):
                    # 对mount这行文本执行替换操作
                    replaceText = "##mount"
                    sedCmd = "sed -i '/^#*.*mount/s/.*/%s/' %s" % (replaceText, resAlterScript)
                    (status, output) = run_cmd(sedCmd)
                    if status != 0:
                        logger.error("Failed to execute sed command!!!")
                        resp = get_error_result("ExecuteSedCmdError")
                cmd = 'umount {}'.format(lv_path)
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
                    # 获删除挂载目录,这个目录应该是个空目录
                    os.removedirs(mount_dir)
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 删除逻辑卷
    def delete_logical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            lvpath = request.data.get('lvpath')
            vgName = request.data.get('vgname')
            if lvpath:
                # 判断如果有自动快照任务，则需要报错提示用户先删除自动快照
                auto_snap_tasks = AutoSnapTask.objects.all()
                allUsedLvs = [element.lvname for element in auto_snap_tasks]
                lvName = os.path.basename(lvpath)
                if lvName in allUsedLvs:
                    logger.error(f"{lvpath} in AutoSnapTask, can't be remove.")
                    resp = get_error_result("LvInAutoSnapTask")
                    return resp

                cmd = 'lvremove -f {}'.format(lvpath)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'contains a filesystem in use' in output:
                        logger.error("Please unmount the logical volume first!!!")
                        resp = get_error_result("UmountLvFirst")
                    elif 'is used by another device' in output:
                        logger.error("The logical volume is currently being used by another device, so it cannot be manipulated!!!")
                        resp = get_error_result("LvIsUsedByOther")
                    else:
                        logger.error("Failed to delete logical volume!!!")
                        resp = get_error_result("DeleteLvError")
                else:
                    lvName = os.path.basename(lvpath)
                    # 删除数据库记录
                    LvInfo.objects.filter(lvname=lvName, vgname=vgName).delete()
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 检查指定逻辑卷是否已经创建了快照
    def check_lv_had_snap(self, lvName):
        cmd = "lvs --noheadings --separator=',' -o lv_name,vg_name,lv_path,origin"
        (status, output) = run_cmd(cmd)
        if status != 0:
            logger.error(f"error for exec : {cmd}, error: {output}")
            raise Exception(f"error for exec : {cmd}, error: {output}")
        lines = [line.strip().strip(',').split(',') for line in output.strip().split('\n')]
        lvs_data = [dict(zip(['lv_name', 'vg_name', 'lv_path', 'origin'], line)) for line in lines]
        for lv in lvs_data:
            if 'origin' not in lv:
                continue
            if lv['origin'] == lvName:
                return True
        return False

    # 逻辑卷扩容
    def extend_logical_volume(self, request, args, kwargs):
        '''
        1、支持没有创建快照的逻辑卷进行在线扩容
        2、已经创建快照的逻辑卷，必须先卸载或者停止使用(进程不能占用)，然后对逻辑卷进行停用才能扩容，最后启用逻辑卷
        '''
        try:
            resp = get_error_result("Success")
            lv_path = request.data.get('lvpath')
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = request.data.get('size')

            lv_name = os.path.basename(lv_path)
            # 对于已经创建快照的逻辑卷无法在线扩容：已经挂载或者已经san映射使用中的逻辑卷扩容，必须先停止访问
            hadSnap = self.check_lv_had_snap(lv_name)
            lvInfo = LvInfo.objects.filter(lvname=lv_name).first()
            if lv_path and lvInfo:
                # 区分是否有创建快照
                if hadSnap:
                    # 停用逻辑卷后，lvextend不能使用-r参数
                    lvextendCmd = 'lvextend -L +{} {}'.format(size, lv_path)
                else:
                    if lvInfo.store_type == "san":
                        # 1、san 类型不需要进行格式化，扩容不需要-r参数
                        lvextendCmd = 'lvextend -L +{} {}'.format(size, lv_path)
                    elif lvInfo.store_type == "nas":
                        checkFsCmd = "blkid %s" % lv_path
                        (status, fstype) = subprocess.getstatusoutput(checkFsCmd)
                        if status == 0:
                            match = re.search(r' TYPE=\"(.*?)\"', fstype)
                            if match:
                                fstype = match.group(1)
                            else:
                                fstype = ''
                        if fstype:
                            # 2、nas 已经做了格式化，扩容需要-r参数
                            lvextendCmd = 'lvextend -r -L +{} {}'.format(size, lv_path)
                        else:
                            # 3、nas 未做格式化，扩容不需要-r参数
                            lvextendCmd = 'lvextend -L +{} {}'.format(size, lv_path)

                # 已经创建快照：先停用逻辑卷
                if hadSnap:
                    stopLvCmd = f"lvchange -an {lv_path}"
                    (status, fstype) = run_cmd(stopLvCmd)
                    # 判断是否是对已经创建快照卷的原卷进行扩宽：如果已经挂载，处于挂载状态禁止扩容
                    if status == 5:
                        logger.error(f"{lv_path} in use")
                        resp = get_error_result("LvIsMountedInUse")
                        return resp
                    elif status != 0:
                        resp = get_error_result("SetLvInactiveFailed")
                        return resp

                (status, output) = run_cmd(lvextendCmd)
                if status != 0:
                    # 扩容失败，再次激活逻辑卷，否则就是不可用状态
                    run_cmd(f"lvchange -ay {lv_path}")
                    resp = get_error_result("lvExtendCmdFailed")
                    return resp
                
                # 已经创建快照：恢复停用的逻辑卷
                if hadSnap:
                    # 激活逻辑卷，不管是否已经停用，执行都不会报错
                    startLvCmd = f"lvchange -ay {lv_path}"
                    (status, fstype) = run_cmd(startLvCmd)
                    if status != 0:
                        resp = get_error_result("SetLvActiveFailed")
                        return resp
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    def backup_logical_volume(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 创建快照
    def create_logical_volume_snap(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            snap_lv_name = request.data.get('snap_name')
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = request.data.get('size')
            lv_path = request.data.get('lvpath')
            if snap_lv_name:
                cmd = 'lvcreate -s -n {} -L {} {}'.format(
                    snap_lv_name, size, lv_path)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    logger.error("Failed to create snapshot!!!")
                    resp = get_error_result("CreateSnapError")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 快照克隆
    def copy_snap(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            snap_path= request.data.get('snap_path')
            lv_name = request.data.get('lvname')
            # 存储类型：nas、fan、other
            storeType = request.data.get('storetype')
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = request.data.get('size')
            vg_name = request.data.get('vgname')

            # 1、创建新的逻辑卷
            if lv_name:
                cmd = 'lvcreate -y -n {} -L {} -W n {}'.format(lv_name, size, vg_name)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'already exists in volume group' in output:
                        logger.error("The logical volume already exists in the volume group!!!")
                        resp = get_error_result("LvExistsInVg")
                    elif 'has insufficient free space' in output:
                        logger.error("The volume group has insufficient available space!!!")
                        resp = get_error_result("VgNoFreeSpace")
                    else:
                        logger.error("Failed to create the logical volume!!!")
                        resp = get_error_result("CreateLvError")
                else:
                    # 数据库记录存储类型
                    values = {
                        "lvname": lv_name,
                        "vgname": vg_name,
                        "store_type": storeType
                    }
                    # 数据插入数据库保存
                    LvInfo.objects.create(**values)
                # 2、格式化逻辑卷
                filesys_type = request.data.get('filesys_type')
                if filesys_type == 'nas':
                    resp = self.format_logical_volume(request, args, kwargs)
                    if resp.get("code") != 0:
                        # 回滚删除新建的逻辑卷
                        self.delete_logical_volume(request, args, kwargs)
                        return resp
                # 3、把快照卷的数据拷贝到新的逻辑卷上
                lv_path = "/dev/{}/{}".format(vg_name, lv_name)
                cmd = 'dd if={} of={}'.format(snap_path, lv_path)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    # 回滚删除新建的逻辑卷
                    self.delete_logical_volume(request, args, kwargs)
                    logger.error("Failed to copy the snap volume!!!")
                    resp = get_error_result("CopySnapError")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp

    # 快照还原
    def restore_logical_volume_snap(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            snap_lv_path = request.data.get('snap_path')
            if snap_lv_path:
                # 判断元原始卷是否被占用
                cmd = f"lvdisplay --noheadings -C -o 'origin,vg_name' {snap_lv_path}"
                (status, output) = run_cmd(cmd)
                if status == 0:
                    originLv = output.split()[0].strip()
                    vg_name = output.split()[1].strip()
                    cmd = f"fuser /dev/{vg_name}/{originLv}"
                    (status, output) = run_cmd(cmd)
                    if status == 0 and output:
                        resp = get_error_result("DeviceBusy")
                        return resp

                cmd = 'lvconvert --merge {}'.format(snap_lv_path)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'invalidated snapshot' in output:
                        logger.error("Invalid snapshot, unable to restore!!!")
                        resp = get_error_result("InvalidSnap")
                    else:
                        logger.error("Snapshot restoration failed!!!")
                        resp = get_error_result("RestoreSnapError")
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return resp


