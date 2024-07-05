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
import ctypes
import sys
import subprocess
import fcntl
from web_manage.common import cmdutils

from rest_framework.decorators import action
from web_manage.common import constants
from web_manage.common.utils import JSONResponse, WebPagination, Authentication, Permission, create_md5, \
    get_error_result
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
from web_manage.hardware.hardRaid.models import hardRaidError
from datetime import datetime


logger = logging.getLogger(__name__)

DEVICE_MAX_COUNT = 32

DEVTYPE_ARRAY =  1
DEVTYPE_DISK  =  2

ARRAY_TYPE_UNKNOWN = 0
ARRAY_TYPE_RAID0 = 1
ARRAY_TYPE_RAID1 = 2
ARRAY_TYPE_RAID5 = 3
ARRAY_TYPE_RAID6 = 4
ARRAY_TYPE_JBOD  = 7

MAX_ARRAYNAME_LEN  = 16
MAX_ARRAY_MEMBERS = 64

# array flags
ARRAY_FLAG_DISABLED = 0x00000001 # The array is disabled */
ARRAY_FLAG_NEEDBUILDING = 0x00000002 # array data need to be rebuilt */
ARRAY_FLAG_REBUILDING = 0x00000004 #array is in rebuilding process */
ARRAY_FLAG_BROKEN = 0x00000008 # broken but may still working */
ARRAY_FLAG_BOOTDISK = 0x00000010 # array has a active partition */
ARRAY_FLAG_BOOTMARK = 0x00000040 # array has boot mark set */
ARRAY_FLAG_NEED_AUTOREBUILD = 0x00000080 # auto-rebuild should start */
ARRAY_FLAG_VERIFYING = 0x00000100 # is being verified */
ARRAY_FLAG_INITIALIZING = 0x00000200 # is being initialized */
ARRAY_FLAG_TRANSFORMING = 0x00000400 # tranform in progress */
ARRAY_FLAG_NEEDTRANSFORM = 0x00000800 # array need tranform */
ARRAY_FLAG_NEEDINITIALIZING = 0x00001000 # the array's initialization hasn't finished*/
ARRAY_FLAG_BROKEN_REDUNDANT = 0x00002000 # broken but redundant (raid6) */
ARRAY_FLAG_RAID15PLUS = 0x80000000 # display this RAID 1 as RAID 1.5 */

# VRC_DEVICE_INFO.CachePolicy */
CACHE_POLICY_NONE = 0
CACHE_POLICY_WRITE_THROUGH = 1
CACHE_POLICY_WRITE_BACK = 2

# disk flags */
DISK_FLAG_DISABLED = 0x00000001 # device is disabled */
DISK_FLAG_BOOTDISK = 0x00000002 # disk has a active partition */
DISK_FLAG_BOOTMARK = 0x00000004 # disk has boot mark set */
DISK_FLAG_SATA = 0x00000010 # SATA or SAS device */
DISK_FLAG_ON_PM_PORT = 0x00000020 # PM port */
DISK_FLAG_SAS = 0x00000040 # SAS device */
DISK_FLAG_IN_ENCLOSURE = 0x00000080 # PathId is enclosure# */
DISK_FLAG_UNINITIALIZED = 0x00010000 # device is not initialized, can't be used to create array */
DISK_FLAG_LEGACY = 0x00020000 # single disk & mbr contains at least one partition */
DISK_FLAG_IS_SPARE = 0x80000000 # is a spare disk */

ARRAY_STATE_REBUILD_START = 1
ARRAY_STATE_REBUILD_ABORT = 2
ARRAY_STATE_REBUILD_PAUSE = ARRAY_STATE_REBUILD_ABORT
ARRAY_STATE_REBUILD_COMPLETE = 3
ARRAY_STATE_VERIFY_START = 4
ARRAY_STATE_VERIFY_ABORT = 5
ARRAY_STATE_VERIFY_COMPLETE = 6
ARRAY_STATE_INITIALIZE_START = 7
ARRAY_STATE_INITIALIZE_ABORT = 8
ARRAY_STATE_INITIALIZE_COMPLETE = 9
ARRAY_STATE_VERIFY_FAILED = 10
ARRAY_STATE_REBUILD_STOP = 11
ARRAY_STATE_SAVE_STATE   = 12
ARRAY_STATE_TRANSFORM_START = 13
ARRAY_STATE_TRANSFORM_ABORT = 14


# SetVdevInfo function parameters */
TARGET_TYPE_DEVICE   =   0
TARGET_TYPE_ARRAY    =   1
AIT_NAME             =   0
AIT_CACHE_POLICY     =   2
DIT_MODE             =   0
DIT_READ_AHEAD       =   1
DIT_WRITE_CACHE      =   2
DIT_TCQ              =   3
DIT_NCQ              =   4
DIT_IDENTIFY         =   5
DIT_SMART            =   6
eventArray = [
    "磁盘被移除",
    "磁盘接入",
    "磁盘出错",
    "阵列重建开始",
    "阵列重建中止",
    "阵列重建结束",
    "热备盘替换",
    "阵列重建失败",
    "阵列校验开始",
    "阵列校验中止",
    "阵列校验失败",
    "阵列校验结束",
    "阵列初始化开始",
    "阵列初始化中止",
    "阵列初始化失败",
    "阵列初始化结束"
    "阵列校验数据错误",
    "阵列转换开始",
    "阵列转换中止",
    "阵列转换失败",
    "阵列转换结束",
    "SMART 检测失败",
    "SMART 检测成功"
]


def arrayToList(array):
    list = []
    for i in array:
       list.append(i)
    return list 


# 定义结构体的字段类型
class VRC_CONTROLLER_INFO(ctypes.Structure):

    _pack_ = 1

    _fields_ = [("ChipType", ctypes.c_uint8),
                ("InterruptLevel", ctypes.c_uint8),
                ("NumBuses", ctypes.c_uint8),
                ("reserved1", ctypes.c_uint8),
                ("szProductID", ctypes.c_uint8 * 36),
                ("szVendorID", ctypes.c_uint8 * 36),
                ("GroupId", ctypes.c_uint32),
                ("pci_tree", ctypes.c_uint8),
                ("pci_bus", ctypes.c_uint8),
                ("pci_device", ctypes.c_uint8),
                ("pci_function", ctypes.c_uint8),
                ("reserved", ctypes.c_uint32),
                ]


class VRC_ARRAY_INFO(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("Name", ctypes.c_uint8 * 16),
        ("reserved", ctypes.c_uint8 * 80),
        ("CreateTime", ctypes.c_uint32),
        ("ArrayType", ctypes.c_uint8),
        ("BlockSizeShift", ctypes.c_uint8),
        ("nDisk", ctypes.c_uint8),
        ("SubArrayType", ctypes.c_uint8),
        ("Flags", ctypes.c_uint32),
        ("RebuildingProgress", ctypes.c_uint32),
        ("RebuiltSectors", ctypes.c_uint64),
        ("TransformSource", ctypes.c_uint32),
        ("TransformTarget", ctypes.c_uint32),
        ("TransformingProgress", ctypes.c_uint32),
        ("Signature", ctypes.c_uint32),
        ("SectorSizeShift", ctypes.c_uint8),
        ("reserved2", ctypes.c_uint8 * 7),
        ("Critical_Members", ctypes.c_uint64),
        ("Members", ctypes.c_uint32 * 64),
    ]

class IDENTIFY_DATA2(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
         ("GeneralConfiguration", ctypes.c_uint16),
         ("NumberOfCylinders", ctypes.c_uint16),
         ("Reserved1", ctypes.c_uint16),
         ("NumberOfHeads", ctypes.c_uint16),
         ("UnformattedBytesPerTrack", ctypes.c_uint16),
         ("UnformattedBytesPerSector", ctypes.c_uint16),
         ("SectorsPerTrack", ctypes.c_uint16),
         ("VendorUnique1", ctypes.c_uint16 * 3),
         ("SerialNumber", ctypes.c_uint16 * 10),
         ("BufferType", ctypes.c_uint16),
         ("BufferSectorSize", ctypes.c_uint16),
         ("NumberOfEccBytes", ctypes.c_uint16),
         ("FirmwareRevision", ctypes.c_uint16 * 4),
         ("ModelNumber", ctypes.c_uint16 * 20),
         ("MaximumBlockTransfer", ctypes.c_uint8),
         ("VendorUnique2", ctypes.c_uint8),
         ("DoubleWordIo", ctypes.c_uint16),
         ("Capabilities", ctypes.c_uint16),
         ("Reserved2", ctypes.c_uint16),
         ("VendorUnique3", ctypes.c_uint8),
         ("PioCycleTimingMode", ctypes.c_uint8),
         ("VendorUnique4", ctypes.c_uint8),
         ("DmaCycleTimingMode", ctypes.c_uint8),
         ("TranslationFieldsValid", ctypes.c_uint16),
         ("NumberOfCurrentCylinders", ctypes.c_uint16),
         ("NumberOfCurrentHeads", ctypes.c_uint16),
         ("CurrentSectorsPerTrack", ctypes.c_uint16),
        ("CurrentSectorCapacity", ctypes.c_uint32),
        ("CurrentMultiSectorSetting", ctypes.c_uint16),
        ("UserAddressableSectors", ctypes.c_uint32),
        ("SingleWordDMASupport", ctypes.c_uint8),
        ("SingleWordDMAActive", ctypes.c_uint8),
        ("MultiWordDMASupport", ctypes.c_uint8),
        ("MultiWordDMAActive", ctypes.c_uint8),
        ("AdvancedPIOModes", ctypes.c_uint8),
        ("Reserved4", ctypes.c_uint8),
        ("MinimumMWXferCycleTime", ctypes.c_uint16),
        ("RecommendedMWXferCycleTime", ctypes.c_uint16),
        ("MinimumPIOCycleTime", ctypes.c_uint16),
        ("MinimumPIOCycleTimeIORDY", ctypes.c_uint16),
        ("Reserved5", ctypes.c_uint16 * 2),
        ("ReleaseTimeOverlapped", ctypes.c_uint16),
        ("ReleaseTimeServiceCommand", ctypes.c_uint16),
        ("MajorRevision", ctypes.c_uint16),
        ("MinorRevision", ctypes.c_uint16),
    ]

class VRC_DISK_INFO(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("ControllerId", ctypes.c_uint8),
        ("PathId", ctypes.c_uint8),
        ("TargetId", ctypes.c_uint8),
        ("DeviceModeSetting", ctypes.c_uint8),
        ("DeviceType", ctypes.c_uint8),
        ("UsableMode", ctypes.c_uint8),

        ("ReadWrite_TCQ_NCQ_Support_Enable", ctypes.c_uint8),#这里是位域，注意大小端
        ("SpinUpMode_SMART_SectorSizeShift", ctypes.c_uint8),#这里是位域，注意大小端

        ("Flags", ctypes.c_uint32),
        ("IdentifyData", IDENTIFY_DATA2),
        ("TotalFree", ctypes.c_uint64),
        ("MaxFree", ctypes.c_uint64),
        ("BadSectors", ctypes.c_uint64),
        ("ParentArrays", ctypes.c_uint32 * 8),
    ]
    
class Union_ARRAY_DISK_INFO(ctypes.Union):

    _pack_ = 1

    _fields_ = [
        ("array", VRC_ARRAY_INFO),
        ("disk", VRC_DISK_INFO),
    ]


class VRC_DEVICE_INFO(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("revision", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 7),
        ("Type", ctypes.c_uint8),
        ("CachePolicy", ctypes.c_uint8),
        ("VBusId", ctypes.c_uint8),
        ("TargetId", ctypes.c_uint8),
        ("Capacity", ctypes.c_uint64),
        ("ParentArray", ctypes.c_uint32),
        ("reserved4", ctypes.c_uint32 * 4),
        ("u", Union_ARRAY_DISK_INFO),
    ]


class VRC_CREATE_ARRAY_PARAMS(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("revision", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 5),
        ("SubDisks", ctypes.c_uint8),
        ("SectorSizeShift", ctypes.c_uint8),
        ("ArrayType", ctypes.c_uint8),
        ("nDisk", ctypes.c_uint8),
        ("BlockSizeShift", ctypes.c_uint8),
        ("CreateFlags", ctypes.c_uint8),
        ("ArrayName", ctypes.c_uint8 * 16),
        ("reserved80", ctypes.c_uint8 * 80),
        ("CreateTime", ctypes.c_uint32),
        ("Capacity", ctypes.c_uint64),
        ("Members", ctypes.c_uint32 * 64),
    ]

class VRC_EVENT(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("Time", ctypes.c_uint32),
        ("DeviceID", ctypes.c_uint32),
        ("EventCode", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("Data", ctypes.c_uint8 * 32),
    ]

class SET_VDEV_INFO(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("target_type", ctypes.c_uint8),
        ("infor_type", ctypes.c_uint8),
        ("param_length", ctypes.c_uint16),
        ("param", ctypes.c_uint8 * 16),
    ]

class ATA_PASSTHROUGH_HEADER(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("idDisk", ctypes.c_uint32),
        ("FeaturesReg", ctypes.c_uint16),
        ("SectorCountReg", ctypes.c_uint16),
        ("LbaLowReg", ctypes.c_uint16),
        ("LbaMidReg", ctypes.c_uint16),
        ("LbaHighReg", ctypes.c_uint16),
        ("DriveHeadReg", ctypes.c_uint8),
        ("CommandReg", ctypes.c_uint8),
        ("Sectors", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("reserve", ctypes.c_uint8),
    ]

class VRC_DRIVER_CAP(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("MaxAdapters", ctypes.c_uint8),
        ("reserved1", ctypes.c_uint8),
        ("MinimumBlockSizeShift", ctypes.c_uint8),
        ("MaximumBlockSizeShift", ctypes.c_uint8),
        ("reserved2", ctypes.c_uint8),
        ("reserved3", ctypes.c_uint8),
        ("reserved4", ctypes.c_uint8),
        ("FeatureFlags", ctypes.c_uint8),
        ("SupportedRAIDTypes", ctypes.c_uint8 * 16),
        ("MaximumArrayMembers", ctypes.c_uint8 * 16),
        ("SupportedCachePolicies", ctypes.c_uint8 * 16),
        ("reserved", ctypes.c_uint32 * 17),
    ]

class PVRC_EVENT(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("Time", ctypes.c_uint32),
        ("DeviceID", ctypes.c_uint32),
        ("EventCode", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
        ("Data", ctypes.c_uint8 * 32),
    ]



from storesys.settings import hardRaidLib

vrcGetControllerCount = hardRaidLib.vrcGetControllerCount
vrcGetControllerInfo = hardRaidLib.vrcGetControllerInfo
vrcGetPhysicalDevices = hardRaidLib.vrcGetPhysicalDevices
vrcGetDeviceInfo = hardRaidLib.vrcGetDeviceInfo
vrcGetLogicalDevices = hardRaidLib.vrcGetLogicalDevices
vrcCalcMaxArrayCapacity = hardRaidLib.vrcCalcMaxArrayCapacity
vrcCreateArray = hardRaidLib.vrcCreateArray
vrcDeleteArray = hardRaidLib.vrcDeleteArray
vrcRemoveDevices = hardRaidLib.vrcRemoveDevices
vrcQueryRemove = hardRaidLib.vrcQueryRemove
vrcRescanDevices = hardRaidLib.vrcRescanDevices
vrcSetArrayState = hardRaidLib.vrcSetArrayState
vrcCreateTransform = hardRaidLib.vrcCreateTransform
vrcSetVdevInfo = hardRaidLib.vrcSetVdevInfo
vrcAddSpareDisk = hardRaidLib.vrcAddSpareDisk
vrcRemoveSpareDisk = hardRaidLib.vrcRemoveSpareDisk
vrcInitDisks = hardRaidLib.vrcInitDisks
vrcGetEvent = hardRaidLib.vrcGetEvent
vrcAtaPassthroughCmd = hardRaidLib.vrcAtaPassthroughCmd

# 定义函数参数类型
#vrcGetControllerCount.argtypes    #空参数不需要指定
vrcGetControllerInfo.argtypes = [ctypes.c_int, ctypes.POINTER(VRC_CONTROLLER_INFO)]
vrcGetPhysicalDevices.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_int]
vrcGetDeviceInfo.argtypes = [ctypes.c_int, ctypes.POINTER(VRC_DEVICE_INFO)]
vrcGetLogicalDevices.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_int]
vrcCalcMaxArrayCapacity.argtypes = [ctypes.c_uint32, ctypes.POINTER(VRC_CREATE_ARRAY_PARAMS), ctypes.POINTER(ctypes.c_uint64)]
vrcCreateArray.argtypes = [ctypes.POINTER(VRC_CREATE_ARRAY_PARAMS)]
vrcDeleteArray.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
vrcRemoveDevices.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
vrcQueryRemove.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
#vrcRescanDevices.argtypes      #空参数不需要指定 
vrcSetArrayState.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
vrcCreateTransform.argtypes = [ctypes.c_uint32, ctypes.POINTER(VRC_CREATE_ARRAY_PARAMS)]
vrcSetVdevInfo.argtypes = [ctypes.c_uint32, ctypes.POINTER(SET_VDEV_INFO)]
vrcAddSpareDisk.argtypes = [ctypes.c_uint32]
vrcRemoveSpareDisk.argtypes = [ctypes.c_uint32]
vrcInitDisks.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
vrcGetEvent.argtypes = [ctypes.POINTER(PVRC_EVENT)]
vrcAtaPassthroughCmd.argtypes = [ctypes.POINTER(ATA_PASSTHROUGH_HEADER)]

# 定义函数返回类型
vrcGetControllerCount.restype = ctypes.c_int
vrcGetControllerInfo.restype = ctypes.c_int
vrcGetPhysicalDevices.restype = ctypes.c_int
vrcGetDeviceInfo.restype = ctypes.c_int
vrcGetLogicalDevices.restype = ctypes.c_int
vrcCalcMaxArrayCapacity.restype = ctypes.c_int
vrcCreateArray.restype = ctypes.c_int
vrcDeleteArray.restype = ctypes.c_int
vrcRemoveDevices.restype = ctypes.c_int
vrcQueryRemove.restype = ctypes.c_int
#vrcRescanDevices.restype      #空返回值不需要指定
vrcSetArrayState.restype = ctypes.c_int
vrcCreateTransform.restype = ctypes.c_int
vrcSetVdevInfo.restype = ctypes.c_int
vrcAddSpareDisk.restype = ctypes.c_int
vrcRemoveSpareDisk.restype = ctypes.c_int
vrcInitDisks.restype = ctypes.c_int
vrcGetEvent.restype = ctypes.c_int
vrcAtaPassthroughCmd.restype = ctypes.c_int

def getEvent():

    theStr = ''
    theEvent = PVRC_EVENT()
    if vrcGetEvent(ctypes.byref(theEvent)) == 0:
        info = VRC_DEVICE_INFO()#class
        if vrcGetDeviceInfo(theEvent.DeviceID, ctypes.byref(info)) == 0:#传入info指针
            if info.Type == DEVTYPE_ARRAY:
                name = bytes(info.u.array.Name).decode('utf-8').replace('\u0000', '')
                theStr = name + ", " + eventArray[theEvent.EventCode]
                return theStr
                
            elif info.Type == DEVTYPE_DISK:
                name = '通道号为：' + str(info.u.disk.PathId) + '磁盘'
                theStr = name + ", " + eventArray[theEvent.EventCode]
                return theStr

            else:
                pass

    return ''

def insertHardRaidErrorTable(desc):
    obj = {
        'desc': desc
    }

    hardRaidError.objects.create(**obj)


def printControlerInfo(info):
    # 将 ctypes 数组转换为字节对象
    #byte_data = byte_array.raw
    # 假设字节数据是 UTF-8 编码的，将其解码为字符串
    #str_data = byte_data.decode('utf-8')

    logger.debug("########################### controller info ##########################")

    logger.debug("芯片类型        :" + str(info.ChipType))#（目前未定义）
    logger.debug("中断号          :" + str(info.InterruptLevel))
    logger.debug("通道数量        :" + str(info.NumBuses))
    logger.debug("芯片型号        :" + bytes(info.szProductID).decode('utf-8'))
    logger.debug("厂商            :" + bytes(info.szVendorID).decode('utf-8'))
    logger.debug("分组标识        :" + str(info.GroupId)) #分组标识，相同标识的控制器可以跨控制器创建阵列
    logger.debug("PCI 子系统编号  :" + str(info.pci_tree))
    logger.debug("PCI 总线号      :" + str(info.pci_bus))
    logger.debug("PCI 设备号      :" + str(info.pci_device)) #（PCIe 设备总是 0）
    logger.debug("PCI 功能号      :" + str(info.pci_function)) #（PCIe 设备总是 0）
    logger.debug("保留字段        :" + str(info.reserved)) #reserverd

    logger.debug("######################################################################")

class getControllers(APIView):

    def post(self, request, *args, **kwargs):
        try:
            ret = {}
            data = []

            controllerCount = vrcGetControllerCount()
            logger.debug('总共 ' + str(controllerCount) + ' 个控制器')

            cmdResult = run_cmd("lspci |grep 'face:000b' |awk '{print $1}'")
            if(cmdResult[0] != 0):
                logger.debug('获取控制器Pci唯一号信息失败！！！')
                ret = get_error_result("GetUniqueNumberError")
                return JSONResponse(ret)
            
            logger.debug('pci唯一号：')
            pciNumber = cmdResult[1].split('\n')
            logger.debug("\t\t" + str(pciNumber))

            # if len(pciNumber) < controllerCount:
            #     logger.debug('控制器Pci唯一号个数与控制器个数不一致！！！')
            #     ret = get_error_result("dataInconsistentNumberOfItemsError")
            #     return JSONResponse(ret)

            info = VRC_CONTROLLER_INFO()
            # 使用match函数
            pattern = re.compile(r'\d+')  # 匹配一个或多个数字
            
            if controllerCount > 0:
                for i in range(controllerCount):
                    if vrcGetControllerInfo(i, ctypes.byref(info)) != 0:#传入info指针
                        logger.debug('获取第 ' + str(i) + ' 个控制器信息失败！！！')
                        continue

                    # pciVersion = run_cmd("lspci -n -s " + pciNumber[i] + " -vvvv |grep PCI |awk '{print $2}' |awk -F'[' '{print $2}'")
                    # if(pciVersion[0] != 0):
                    #     logger.debug('获取第 ' + str(i) + ' 个控制器Pci版本信息失败！！！')
                    #     continue 

                    # result = pattern.match(pciVersion[1])
                    # if result == None:
                    #     pciVersion[1] = ''
                    
                    # pciWidth = run_cmd("lspci -n -s " + pciNumber[i] + " -vvvv |grep 'downgraded' |awk '{print $6}'")
                    # if(pciWidth[0] != 0):
                    #     logger.debug('获取第 ' + str(i) + ' 个控制器Pci带宽信息失败！！！')
                    #     continue 

                    printControlerInfo(info)
                    obj = {}
                    obj['id'] = i + 1
                    obj['ChipType'] = info.ChipType
                    obj['InterruptLevel'] = info.InterruptLevel
                    obj['NumBuses'] = info.NumBuses
                    obj['szProductID'] = bytes(info.szProductID).decode('utf-8').replace('\u0000', '')#string 原来数组中的空字符会转换成\u0000，所以用replace去掉\u0000
                    obj['szVendorID'] = bytes(info.szVendorID).decode('utf-8').replace('\u0000', '')#string
                    obj['GroupId'] = info.GroupId
                    obj['pci_tree'] = info.pci_tree
                    obj['pci_bus'] = info.pci_bus
                    obj['pci_device'] = info.pci_device
                    obj['pci_function'] = info.pci_function
                    obj['reserved'] = info.reserved
                    # if pciVersion[1] == '':
                    #     obj['PCIeVersion'] = "15.0"
                    # else:
                    #     obj['PCIeVersion'] = str(float(pciVersion[1])/100.0)
                    # if pciWidth[1] == '':
                    #     obj['pciWidth'] = "x63"
                    # else:
                    #     obj['pciWidth'] = pciWidth[1]

                    obj['PCIeVersion'] = "3.0"
                    obj['pciWidth'] = "x4"
                    
                    
                    data.append(obj)

            ret = get_error_result("Success", data)

            return JSONResponse(ret)
        
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("getControllerInfoError")

            JSONResponse(resp)
        


def printArrayInfo(info):
     
    logger.debug("\t\t########################### array info ##########################")

    logger.debug("\t\t阵列名称                  ：" + bytes(info.Name).decode('utf-8').replace('\u0000', ''))
    logger.debug("\t\t阵列创建时间              ：" + str(info.CreateTime)); #TIME_RECORD CreateTime;
    if info.ArrayType == ARRAY_TYPE_RAID0:
        if info.SubArrayType == ARRAY_TYPE_RAID1:
            logger.debug("\t\t阵列类型                  ：RAID10 阵列")
        else:
            logger.debug("\t\t阵列类型                  ：RAID0 阵列")
        
    elif info.ArrayType == ARRAY_TYPE_RAID1:
        logger.debug("\t\t阵列类型                  ：RAID1 阵列")
    elif info.ArrayType == ARRAY_TYPE_RAID5:
        logger.debug("\t\t阵列类型                  ：RAID5 阵列")
    elif info.ArrayType == ARRAY_TYPE_JBOD:
        logger.debug("\t\t阵列类型                  ：JBOD 阵列")
    else:
        logger.debug("\t\t阵列类型                  ：未知")
	
    logger.debug("\t\t块大小                    ：" + str((2 << info.BlockSizeShift) / 2 * 512) + " (字节)")
    logger.debug("\t\t成员盘个数                ：" + str(info.nDisk))
	
    if info.SubArrayType == ARRAY_TYPE_RAID0:
        logger.debug("\t\t二级阵列类型              ：RAID0 阵列（或 RAID10 阵列）")
    elif info.SubArrayType == ARRAY_TYPE_RAID1:
        logger.debug("\t\t二级阵列类型              ：RAID1 阵列")
    elif info.SubArrayType == ARRAY_TYPE_RAID5:
        logger.debug("\t\t二级阵列类型              ：RAID5 阵列")
    elif info.SubArrayType == ARRAY_TYPE_JBOD:
        logger.debug("\t\t二级阵列类型              ：JBOD 阵列")
    else:
        logger.debug("\t\t二级阵列类型              ：未知")
	
    arrayFlag = 0
    logger.debug("\t\t阵列标志位                 ：")
    if info.Flags & ARRAY_FLAG_DISABLED:
        logger.debug("      阵列离线 ")
        arrayFlag = arrayFlag + 1
    if info.Flags & ARRAY_FLAG_NEEDBUILDING:
        logger.debug("      阵列需重建 ")
        arrayFlag = arrayFlag + 1
    if info.Flags & ARRAY_FLAG_REBUILDING:
        logger.debug("      阵列正在重建 ")
        arrayFlag = arrayFlag + 1
    if info.Flags & ARRAY_FLAG_BROKEN:
        logger.debug("      阵列缺少磁盘 ")
        arrayFlag = arrayFlag + 1
    if info.Flags & ARRAY_FLAG_VERIFYING:
        logger.debug("      阵列正在校验 ")
        arrayFlag = arrayFlag + 1
    if info.Flags & ARRAY_FLAG_INITIALIZING:
        logger.debug("      阵列正在初始化 ")
        arrayFlag = arrayFlag + 1
    if info.Flags & ARRAY_FLAG_TRANSFORMING:

        logger.debug("      阵列正在转换级别 ")
        arrayFlag = arrayFlag + 1
        logger.debug("\t\t\t\t	阵列级别转换源 ID                 ：" + str(info.TransformSource))
        logger.debug("\t\t\t\t	阵列级别转换目标 ID               ：" + str(info.TransformTarget))

    if info.Flags & ARRAY_FLAG_NEEDINITIALIZING:
        logger.debug("      阵列初始化未完成")
        arrayFlag = arrayFlag + 1
    if arrayFlag == 0:
        logger.debug("      正常 ")
    logger.debug('\r\n')

    logger.debug("\t\t重建进度                  ：%" + str(info.RebuildingProgress / 100.0))
    if info.RebuiltSectors > (2 << 32):
        logger.debug("\t\t重建扇区位置              ：-1")
    else:
        logger.debug("\t\t重建扇区位置              ：" +  str(info.RebuiltSectors))
    logger.debug("\t\t阵列级别转换进度          ：%" + str(info.TransformingProgress / 100.0))
    logger.debug("\t\t阵列标签值                ：" + str(info.Signature))
    logger.debug("\t\t逻辑扇区大小              ：" + str((2 << info.SectorSizeShift) / 2 * 512))
    logger.debug("\t\t失效磁盘标记(bitmask)     ：" + str(info.Critical_Members))
    logger.debug("\t\t成员盘 ID 数组            :")
    for i in range(MAX_ARRAY_MEMBERS):
        if info.Members[i] != 4294967295:
            logger.debug("\t\t" + str(info.Members[i]) + ' ')
    logger.debug('\r\n')

    logger.debug("\t\t######################################################################")

def printDiskInfo(info):

    logger.debug("\t\t########################### disk info ##########################")

    logger.debug("\t\t控制器编号            ：" + str(info.ControllerId))#从 0 开始
    logger.debug("\t\t通道号                ：" + str(info.PathId))
    logger.debug("\t\t目标编号              ：" + str(info.TargetId))#（仅当一个通道支持多个设备时）
    logger.debug("\t\t设备传输模式          ：" + str(info.DeviceModeSetting))
    logger.debug("\t\t设备类型              ：" + str(info.DeviceType))
    logger.debug("\t\t使用模式              ：" + str(info.UsableMode))

    value = 0
    if sys.byteorder == 'big':#大端模式下，注意位域
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x80 > 0: value = 1 
        else: value = 0
        logger.debug("\t\t是否支持 readahead    " + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x40 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 readahead  ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x20 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持 writecache   ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x10 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 writecache ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x08 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持   TCQ        ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x04 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 TCQ        ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x02 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持 NCQ          ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x01 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 NCQ        ：" + str(value))

        logger.debug("\t\t微调模式              ：" + str(info.SpinUpMode_SMART_SectorSizeShift & 0xc0 >> 6))

        if info.SpinUpMode_SMART_SectorSizeShift & 0x20 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持   SMART      ：" + str(value))

        if info.SpinUpMode_SMART_SectorSizeShift & 0x10 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 SMART      ：" + str(value))

        logger.debug("\t\t扇区大小转换          ：" + str(info.SpinUpMode_SMART_SectorSizeShift & 0x0F))
                        
    else:
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x80 > 0: value = 1 
        else: value = 0
        logger.debug("\t\t是否启用了 NCQ        ：" + str(value))
        
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x40 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持 NCQ          ：" + str(value))
        
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x20 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 TCQ        ：" + str(value))
        
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x10 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持   TCQ        ：" + str(value))
        
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x08 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 writecache ：" + str(value))
        
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x04 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持 writecache   ：" + str(value))
        
        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x02 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了 readahead  ：" + str(value))

        if info.ReadWrite_TCQ_NCQ_Support_Enable & 0x01 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持 readahead    " + str(value))

        logger.debug("\t\t扇区大小转换              ：" + str((info.SpinUpMode_SMART_SectorSizeShift & 0xF0) >> 4))

        if info.SpinUpMode_SMART_SectorSizeShift & 0x08 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否启用了   SMART      ：" + str(value))

        if info.SpinUpMode_SMART_SectorSizeShift & 0x04 > 0: value = 1
        else: value = 0
        logger.debug("\t\t是否支持 SMART      ：" + str(value))

        logger.debug("\t\t微调模式          ：" + str(info.SpinUpMode_SMART_SectorSizeShift & 0x03))

    flagCnt = 0
    logger.debug("\t\t磁盘标志              : ")
    if info.Flags & DISK_FLAG_DISABLED:
        logger.debug("       磁盘离线") 
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_BOOTDISK:
        logger.debug("       磁盘有一个活动分区")
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_BOOTMARK:
        logger.debug("       磁盘已设置启动标记")
        flagCnt = flagCnt + 1
    if (info.Flags & DISK_FLAG_SATA) and (info.Flags & DISK_FLAG_SAS) == 0:
        logger.debug("      SATA磁盘")
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_ON_PM_PORT:
        logger.debug("       PM端口" )
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_SAS:
        logger.debug("       SAS磁盘")
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_IN_ENCLOSURE:
        logger.debug("       磁盘在expander上")
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_UNINITIALIZED:
        logger.debug("       磁盘未初始化")
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_LEGACY:
        logger.debug("       磁盘为legacy设备")
        flagCnt = flagCnt + 1
    if info.Flags & DISK_FLAG_IS_SPARE:
        logger.debug("       磁盘为备用盘")
        flagCnt = flagCnt + 1
    if flagCnt == 0:
        logger.debug("      未知")
    logger.debug("\r\n")

    logger.debug("\t\t磁盘型号              : " + bytes(info.IdentifyData.ModelNumber).decode('utf-8').replace('\u0000', ''))

    logger.debug("\t\t固件版本              : ")
    for i in range(4):

        logger.debug("\t\t" + chr((info.IdentifyData.FirmwareRevision[i] & 0xFF00) >> 8))#将ascii码转换成字符
        logger.debug("\t\t" + chr(info.IdentifyData.FirmwareRevision[i] & 0xFF))#将ascii码转换成字符
    logger.debug("\r\n")

    logger.debug("\t\t序列号                : ")
    for i in range(10):   

        logger.debug("\t\t" + chr((info.IdentifyData.SerialNumber[i] & 0xFF00) >> 8))#将ascii码转换成字符
        logger.debug("\t\t" + chr(info.IdentifyData.SerialNumber[i] & 0xFF))#将ascii码转换成字符
    logger.debug("\r\n")

    logger.debug("\t\t总可用容量            ：" + str(info.TotalFree * 512) + ' (字节)')
    logger.debug("\t\t最大空闲区间容量      ：" + str(info.MaxFree * 512) + ' (字节)')


    logger.debug("\t\t坏扇区                : " + str(info.BadSectors))

    logger.debug("\t\t所属阵列 ID           :");#所属阵列 ID，一个磁盘可以属于多个阵列
    for i in range(8):

        logger.debug("\t\t" + str(info.ParentArrays[i]))
    logger.debug("\r\n");   

    logger.debug("\t\t######################################################################")

def printDeviceInfo(deviceId, info):

    logger.debug("########################### deviceId: " + str(deviceId) + " info ##########################")

    logger.debug("结构体大小          ：" + str(info.dwSize))#（结构体大小,设置为 sizeof(VRC_DEVICE_INFO)）
    logger.debug("结构体版本          ：" + str(info.revision))

    if info.Type == DEVTYPE_ARRAY:
	
        logger.debug("设备类型        ：阵列设备")
        if info.ParentArray != 0xFFFFFFFF:             
            logger.debug("\t\t所属阵列 ID : " + str(info.ParentArray))#所属阵列 ID
        else:
            logger.debug("\t\t所属阵列 ID : 0")#所属阵列 ID
        
        printArrayInfo(info.u.array)
	
    elif info.Type == DEVTYPE_DISK:

        logger.debug("设备类型        ：物理盘设备")
        printDiskInfo(info.u.disk)

    else:
        logger.debug("设备类型        ：未知")

    if info.CachePolicy == CACHE_POLICY_NONE:
        logger.debug("缓存策略        ：无缓存")
    elif info.CachePolicy == CACHE_POLICY_WRITE_THROUGH:
        logger.debug("缓存策略        ：直写缓存")
    elif info.CachePolicy == CACHE_POLICY_WRITE_BACK:
        logger.debug("缓存策略        ：回写缓存")
    else:
        logger.debug("缓存策略        ：未知")

    logger.debug("逻辑总线号          ：" + str(info.VBusId))
    logger.debug("系统磁盘目标 ID          ：" + str(info.TargetId));#系统磁盘目标 ID。0xFF 表示无效
    logger.debug("设备容量            ：" + str(info.Capacity * 512) + ' (字节)')

    logger.debug("######################################################################")

def print_VRC_CREATE_ARRAY_PARAMS(info):
    
    logger.debug("########################### VRC_CREATE_ARRAY_PARAMS info ##########################")

    logger.debug('dwSize           : ' + str(info.dwSize))
    logger.debug('revision         : ' + str(info.revision))
    logger.debug('SubDisks         : ' + str(info.SubDisks))
    logger.debug('SectorSizeShift  : ' + str(info.SectorSizeShift))
    logger.debug('ArrayType        : ' + str(info.ArrayType))
    logger.debug('nDisk            : ' + str(info.nDisk))
    logger.debug('BlockSizeShift   : ' + str(info.BlockSizeShift))
    logger.debug('CreateFlags      : ' + str(info.CreateFlags))
    logger.debug('ArrayName        : ' + bytes(info.ArrayName).decode('utf-8').replace('\u0000', ''))
    logger.debug('CreateTime       : ' + str(info.CreateTime))
    logger.debug('Capacity         : ' + str(info.Capacity))
    logger.debug('Members          :')
    for i in info.Members:
        logger.debug("\t\t" + str(i))
    logger.debug('')

    logger.debug("###################################################################################")

def print_SET_VDEV_INFO(info):

    logger.debug("########################### SET_VDEV_INFO info ##########################")

    logger.debug('target_type :' + str(info.target_type))
    logger.debug('infor_type :' + str(info.infor_type))
    logger.debug('param_length :' + str(info.param_length))

    logger.debug('param :')
    if info.infor_type == 0 :#名字
        for index in info.param:
            logger.debug("\t\t" + chr(index))
        logger.debug('\r\n')

    else:#缓存策略
        logger.debug(info.param[0])

    logger.debug("########################### ################## ##########################")

smartReferenceTable = [
    {"id":1, "desc":"Raw_Read_Error_Rate", "threshold":50},
    {"id": 2, "desc": "Throughput_Performance", "threshold":0},
    {"id":3, "desc":"Spin_Up_Time",  "threshold":0},
    {"id":4, "desc":"Start_Stop_Count", "threshold":0},
    {"id":5, "desc":"Readllocated_Sector_Count", "threshold":0},
    {"id":6, "desc":"Read_Channel_Margin", "threshold":0},
    {"id":7, "desc":"Seek_Error_Rate", "threshold":0},
    {"id":8, "desc":"Seek_Time_Performance", "threshold":0},
    {"id":9, "desc":"Power_On_Hours", "threshold":50},
    {"id":10, "desc":"Spin_Retry_count", "threshold":0},
    {"id":11, "desc":"Recalibration_Retries", "threshold":0},
    {"id":12, "desc":"Power_Cycle_Count", "threshold":0},
    {"id":13, "desc":"Soft_Read_Error_Rate", "threshold":0},
    {"id":170, "desc":"Unknown_Attribute", "threshold":10},
    {"id":171, "desc":"Unknown_Attribute", "threshold":10},
    {"id":180, "desc":"Unknown_Attribute", "threshold":10},
    {"id":183, "desc":"Sata_Downshift_Error_Count", "threshold":0},
    {"id":184, "desc":"End_To_End_Error", "threshold":0},
    {"id":185, "desc":"Head_Stability", "threshold":0},
    {"id":186, "desc":"Induced_Op_Vibration_Detection", "threshold":0},
    {"id":187, "desc":"Reported_Uncorrectable_Error", "threshold":0},
    {"id":188, "desc":"Command_Timeout", "threshold":0},
    {"id":189, "desc":"High_Fly_Writes", "threshold":0},
    {"id":190, "desc":"Airflow_Temperature", "threshold":0},
    {"id":191, "desc":"G_Sense_Error_Rate", "threshold":0},
    {"id":192, "desc":"Power_Off_Retract_Count", "threshold":0},
    {"id":193, "desc":"Load_Cycle_Count", "threshold":0},
    {"id":194, "desc":"Temperature_Celsius","threshold": 0},
    {"id":195, "desc":"Hardware_Ecc_Recovered", "threshold":0},
    {"id":196, "desc":"Reallocation_Event_Count", "threshold":0},
    {"id":197, "desc":"Current_Pending_Sector_Count", "threshold":0},
    {"id":198, "desc":"Uncorrectable_Sector_Count", "threshold":0},
    {"id":199, "desc":"Ultra_Dma_Crc_Error_Count", "threshold":0},
    {"id":200, "desc":"Write_Error_Rate", "threshold":0},
    {"id":201, "desc":"Soft_Read_Error_Rate", "threshold":0},
    {"id":202, "desc":"Data_Address_Mark_Errors", "threshold":0},
    {"id":203, "desc":"Run_Out_Cancel", "threshold":0},
    {"id":204, "desc":"Soft_Ecc_Correction", "threshold":0},
    {"id":205, "desc":"Thermal_Asperity_Rate", "threshold":0},
    {"id":206, "desc":"Flying_Height", "threshold":0},
    {"id":207, "desc":"Spin_High_Current", "threshold":0},
    {"id":208, "desc":"Spin_Buzz", "threshold":0},
    {"id":209, "desc":"Offline_Seek_Performance", "threshold":0},
    {"id":211, "desc":"Vibration_During_Write", "threshold":0},
    {"id":212, "desc":"Shock_During_Write", "threshold":0},
    {"id":218, "desc":"Unknown_Attribute", "threshold":50},
    {"id":220, "desc":"Disk_Shift", "threshold":0},
    {"id":221, "desc":"G_Sense_Erroe_Rate", "threshold":0},
    {"id":222, "desc":"Loaded_Hours", "threshold":0},
    {"id":223, "desc":"Load/Unload_Retry_Count", "threshold":0},
    {"id":224, "desc":"Load_Friction", "threshold":0},
    {"id":225, "desc":"Load/Unload_Cycle_Count", "threshold":0},
    {"id":226, "desc":"Load_In_Time", "threshold":0},
    {"id":227, "desc":"Torque_Amplification_Count", "threshold":0},
    {"id":228, "desc":"Power_Off_Retract_Cycle", "threshold":0},
    {"id":230, "desc":"Gmr_Head_Amplitude", "threshold":0},
    {"id":231, "desc":"Temperature_Celsius", "threshold":0},
    {"id":232, "desc":"Endurance_Remaining", "threshold":0},
    {"id":233, "desc":"Media_Wearout_Indicator", "threshold":0},
    {"id":240, "desc":"Head_Flying_Hours", "threshold":0},
    {"id":241, "desc":"Total_Lbas_Written", "threshold":0},
    {"id":242, "desc":"Total_Labs_Read", "threshold":5},
    {"id":250, "desc":"Read_Error_Retry_Rate", "threshold":0},
    {"id":254, "desc":"Free_Fall_Protection", "threshold":0},
    
]


class smartInfo(ctypes.Structure):
    _pack_ = 1

    _fields_ = [
        ("header", ATA_PASSTHROUGH_HEADER),
        ("data", ctypes.c_uint8 * 1024),
    ]


class ata_smart_attribute(ctypes.Structure):
    _pack_ = 1

    _fields_ = [
        ("id", ctypes.c_uint8),
        ("flags", ctypes.c_uint16),
        ("current", ctypes.c_uint8),
        ("worst", ctypes.c_uint8),
        ("raw", ctypes.c_uint8 * 6),
        ("reserv", ctypes.c_uint8),
    ]

NUMBER_ATA_SMART_ATTRIBUTES = 30


para = smartInfo()#class

class getSpecificDiskSmart(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id':openapi.Schema(type=openapi.TYPE_INTEGER, description='id'),
        },
        required=['id'],
    ))

    def post(self, request, *args, **kwargs):

        ret = {}

        id = request.data.get('id')

        try:

    
            para.header.idDisk = ctypes.c_uint32(id)
            para.header.CommandReg = ctypes.c_uint8(176)#0xB0
            para.header.FeaturesReg = ctypes.c_uint16(208)#0xD0
            para.header.LbaLowReg = ctypes.c_uint16(0)
            para.header.LbaMidReg = ctypes.c_uint16(79)#0x4F
            para.header.LbaHighReg = ctypes.c_uint16(194)#0xC2
            para.header.SectorCountReg = ctypes.c_uint16(0)
            para.header.Sectors = ctypes.c_uint16(2)
            para.header.protocol = ctypes.c_uint8(1)
            para.header.DriveHeadReg = ctypes.c_uint8(0xA0)
            para.header.reserve = ctypes.c_uint8(0)

            if vrcAtaPassthroughCmd(ctypes.byref(para.header)) != 0:
                ret = get_error_result("GetSmartInfoError")
                return JSONResponse(ret)
            
            logger.debug(f"idDisk: {para.header.idDisk}")
            logger.debug(f"FeaturesReg:{para.header.FeaturesReg}")
            logger.debug(f"SectorCountReg:{para.header.SectorCountReg}")
            logger.debug(f"LbaLowReg:{para.header.LbaLowReg}")
            logger.debug(f"LbaMidReg:{para.header.LbaMidReg}")
            logger.debug(f"LbaHighReg:{para.header.LbaHighReg}")
            logger.debug(f"DriveHeadReg:{para.header.DriveHeadReg}")
            logger.debug(f"CommandReg:{para.header.CommandReg}")
            logger.debug(f"Sectors:{para.header.Sectors}")
            logger.debug(f"protocol:{para.header.protocol}")
            logger.debug(f"reserve:{para.header.reserve}")

            smartPtr = ctypes.cast(ctypes.byref(para.data, 22), ctypes.POINTER(ata_smart_attribute))

            smartInfoList = []

            for index in range(NUMBER_ATA_SMART_ATTRIBUTES):

                if smartPtr[index].id == 0:
                    continue

                obj = {}
                name = "Unknown_Attribute"
                threshold = 0
                
                for ele in smartReferenceTable:
                    if smartPtr[index].id == ele['id']:
                        name = ele['desc']
                        threshold = ele['threshold']

                obj['id'] = smartPtr[index].id
                obj['name'] = name
                obj['threshold'] = threshold
                obj['worst'] = smartPtr[index].worst
                obj['current'] = smartPtr[index].current
                obj['raw'] = []
                for j in range(6):
                    obj['raw'].append(smartPtr[index].raw[j])
                
                obj['statusOk'] = True
                if smartPtr[index].current < threshold:
                    obj['statusOk'] = False
                smartInfoList.append(obj)
    
            ret = get_error_result("Success", smartInfoList)

            return JSONResponse(ret)
        
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("GetSmartInfoError")

            JSONResponse(resp)



class getSpecificPhysicalDisk(APIView):

    def post(self, request, *args, **kwargs):

        id = request.data.get('id')
        ret = {}
        data = {}

        try:

            info = VRC_DEVICE_INFO()#class

            if vrcGetDeviceInfo(id, ctypes.byref(info)) != 0:#传入info指针
                logger.debug('获取设备id为： ' + str(id) + ' 的物理磁盘信息失败！！！')
                ret['code'] = -2
                ret['msg'] = '获取物理磁盘信息失败'
                ret['data'] = data

            else:
                printDeviceInfo(id, info)
                obj = {}
                obj['id'] = id
                obj['dwSize'] = info.dwSize
                obj['revision'] = info.revision

                obj['Type'] = info.Type
                obj['CachePolicy'] = info.CachePolicy
                obj['VBusId'] = info.VBusId
                obj['TargetId'] = info.TargetId
                obj['Capacity'] = info.Capacity * 512
                obj['ParentArray'] = info.ParentArray
                
                obj['ControllerId'] = info.u.disk.ControllerId + 1
                obj['PathId'] = info.u.disk.PathId + 1
                obj['TargetId'] = info.u.disk.TargetId
                obj['DeviceModeSetting'] = info.u.disk.DeviceModeSetting
                obj['DeviceType'] = info.u.disk.DeviceType
                obj['UsableMode'] = info.u.disk.UsableMode
                
                if sys.byteorder == 'big':#大端模式下，注意位域
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x80 > 0: obj['ReadAheadSupported'] = 1 
                    else: obj['ReadAheadSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x40 > 0: obj['ReadAheadEnabled'] = 1
                    else: obj['ReadAheadEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x20 > 0: obj['WriteCacheSupported'] = 1
                    else: obj['WriteCacheSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x10 > 0: obj['WriteCacheEnabled'] = 1
                    else: obj['WriteCacheEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x08 > 0: obj['TCQSupported'] = 1
                    else: obj['TCQSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x04 > 0: obj['TCQEnabled'] = 1
                    else: obj['TCQEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x02 > 0: obj['NCQSupported'] = 1
                    else: obj['NCQSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x01 > 0: obj['NCQEnabled'] = 1
                    else: obj['NCQEnabled'] = 0

                    obj['SpinUpMode'] = (info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0xc0) >> 6
                    if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x20 > 0: obj['SMARTSupported'] = 1
                    else: obj['SMARTSupported'] = 0
                    if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x10 > 0: obj['SMARTEnabled'] = 1
                    else: obj['SMARTEnabled'] = 0
                    obj['SectorSizeShift'] = info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x0F
                
                else:
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x80 > 0: obj['NCQEnabled'] = 1 
                    else: obj['NCQEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x40 > 0: obj['NCQSupported'] = 1
                    else: obj['NCQSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x20 > 0: obj['TCQEnabled'] = 1
                    else: obj['TCQEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x10 > 0: obj['TCQSupported'] = 1
                    else: obj['TCQSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x08 > 0: obj['WriteCacheEnabled'] = 1
                    else: obj['WriteCacheEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x04 > 0: obj['WriteCacheSupported'] = 1
                    else: obj['WriteCacheSupported'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x02 > 0: obj['ReadAheadEnabled'] = 1
                    else: obj['ReadAheadEnabled'] = 0
                    if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x01 > 0: obj['ReadAheadSupported'] = 1
                    else: obj['ReadAheadSupported'] = 0

                    obj['SectorSizeShift'] = (info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0xF0) >> 4
                    if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x08 > 0: obj['SMARTEnabled'] = 1
                    else: obj['SMARTEnabled'] = 0
                    if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x04 > 0: obj['SMARTSupported'] = 1
                    else: obj['SMARTSupported'] = 0
                    obj['SpinUpMode'] = info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x03

                flagCnt = 0
                flagString = ''
                for id in info.u.disk.ParentArrays:
                    if id != 0:
                        deviceInfo = VRC_DEVICE_INFO()#class
                        if vrcGetDeviceInfo(id, ctypes.byref(deviceInfo)) != 0:#传入deviceInfo指针
                            logger.debug('获取父设备id为： ' + str(id) + ' 的设备信息失败！！！')
                            continue
                        else:
                            if deviceInfo.Type == DEVTYPE_ARRAY:
                                if len(flagString) == 0:
                                    flagString = flagString + '磁盘阵列'
                                flagString = flagString + '(' + bytes(deviceInfo.u.array.Name).decode('utf-8').replace('\u0000', '') + ')'
                if len(flagString) != 0:
                    flagString = flagString + ', '

                if info.u.disk.Flags & DISK_FLAG_DISABLED:
                    flagString = flagString + "磁盘离线 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_BOOTDISK:
                    flagString = flagString + "磁盘有一个活动分区 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_BOOTMARK:
                    flagString = flagString + "磁盘已设置启动标记 "
                    flagCnt = flagCnt + 1
                if (info.u.disk.Flags & DISK_FLAG_SATA) and (info.u.disk.Flags & DISK_FLAG_SAS) == 0:
                    flagString = flagString + "SATA磁盘 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_ON_PM_PORT:
                    flagString = flagString + "PM端口 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_SAS:
                    flagString = flagString + "SAS磁盘 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_IN_ENCLOSURE:
                    flagString = flagString + "磁盘在expander上 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_UNINITIALIZED:
                    flagString = flagString + "磁盘未初始化 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_LEGACY:
                    flagString = flagString + "磁盘为legacy设备 "
                    flagCnt = flagCnt + 1
                if info.u.disk.Flags & DISK_FLAG_IS_SPARE:
                    flagString = flagString + "磁盘为备用盘 "
                    flagCnt = flagCnt + 1
                if flagCnt == 0:
                    flagString = flagString + "未知"

                obj['Flags'] = flagString
                if obj['Flags'].find('磁盘未初始化') != -1:
                    insertHardRaidErrorTable('所在槽位号:' + str(obj['PathId']) + ' 的物理磁盘未初始化')

                obj['GeneralConfiguration'] = info.u.disk.IdentifyData.GeneralConfiguration
                obj['NumberOfCylinders'] = info.u.disk.IdentifyData.NumberOfCylinders
                obj['Reserved1'] = info.u.disk.IdentifyData.Reserved1
                obj['NumberOfHeads'] = info.u.disk.IdentifyData.NumberOfHeads
                obj['UnformattedBytesPerTrack'] = info.u.disk.IdentifyData.UnformattedBytesPerTrack
                obj['UnformattedBytesPerSector'] = info.u.disk.IdentifyData.UnformattedBytesPerSector
                obj['SectorsPerTrack'] = info.u.disk.IdentifyData.SectorsPerTrack
                obj['VendorUnique1'] = arrayToList(info.u.disk.IdentifyData.VendorUnique1)

                SerialNumberString = ''
                for i in range(10):
                    SerialNumberString = SerialNumberString + chr((info.u.disk.IdentifyData.SerialNumber[i] & 0xFF00) >> 8)#将ascii码转换成字符
                    SerialNumberString = SerialNumberString + chr(info.u.disk.IdentifyData.SerialNumber[i] & 0xFF)#将ascii码转换成字符
                obj['SerialNumber'] = SerialNumberString.replace(' ','')

                obj['BufferType'] = info.u.disk.IdentifyData.BufferType
                obj['BufferSectorSize'] = info.u.disk.IdentifyData.BufferSectorSize
                obj['NumberOfEccBytes'] = info.u.disk.IdentifyData.NumberOfEccBytes

                hardVersionString = ''
                for i in range(4):
                    hardVersionString = hardVersionString + chr((info.u.disk.IdentifyData.FirmwareRevision[i] & 0xFF00) >> 8)#将ascii码转换成字符
                    hardVersionString = hardVersionString + chr(info.u.disk.IdentifyData.FirmwareRevision[i] & 0xFF)#将ascii码转换成字符
                obj['FirmwareRevision'] = hardVersionString

                obj['ModelNumber'] = bytes(info.u.disk.IdentifyData.ModelNumber).decode('utf-8').replace('\u0000', '')
                obj['MaximumBlockTransfer'] = info.u.disk.IdentifyData.MaximumBlockTransfer
                obj['VendorUnique2'] = info.u.disk.IdentifyData.VendorUnique2
                obj['DoubleWordIo'] = info.u.disk.IdentifyData.DoubleWordIo
                obj['Capabilities'] = info.u.disk.IdentifyData.Capabilities
                obj['Reserved2'] = info.u.disk.IdentifyData.Reserved2
                obj['VendorUnique3'] = info.u.disk.IdentifyData.VendorUnique3
                obj['PioCycleTimingMode'] = info.u.disk.IdentifyData.PioCycleTimingMode
                obj['VendorUnique4'] = info.u.disk.IdentifyData.VendorUnique4
                obj['DmaCycleTimingMode'] = info.u.disk.IdentifyData.DmaCycleTimingMode
                obj['TranslationFieldsValid'] = info.u.disk.IdentifyData.TranslationFieldsValid
                obj['NumberOfCurrentCylinders'] = info.u.disk.IdentifyData.NumberOfCurrentCylinders
                obj['NumberOfCurrentHeads'] = info.u.disk.IdentifyData.NumberOfCurrentHeads
                obj['CurrentSectorsPerTrack'] = info.u.disk.IdentifyData.CurrentSectorsPerTrack
                obj['CurrentSectorCapacity'] = info.u.disk.IdentifyData.CurrentSectorCapacity
                obj['CurrentMultiSectorSetting'] = info.u.disk.IdentifyData.CurrentMultiSectorSetting
                obj['UserAddressableSectors'] = info.u.disk.IdentifyData.UserAddressableSectors
                obj['SingleWordDMASupport'] = info.u.disk.IdentifyData.SingleWordDMASupport
                obj['SingleWordDMAActive'] = info.u.disk.IdentifyData.SingleWordDMAActive
                obj['MultiWordDMASupport'] = info.u.disk.IdentifyData.MultiWordDMASupport
                obj['MultiWordDMAActive'] = info.u.disk.IdentifyData.MultiWordDMAActive
                obj['AdvancedPIOModes'] = info.u.disk.IdentifyData.AdvancedPIOModes
                obj['Reserved4'] = info.u.disk.IdentifyData.Reserved4
                obj['MinimumMWXferCycleTime'] = info.u.disk.IdentifyData.MinimumMWXferCycleTime
                obj['RecommendedMWXferCycleTime'] = info.u.disk.IdentifyData.RecommendedMWXferCycleTime
                obj['MinimumPIOCycleTime'] = info.u.disk.IdentifyData.MinimumPIOCycleTime
                obj['MinimumPIOCycleTimeIORDY'] = info.u.disk.IdentifyData.MinimumPIOCycleTimeIORDY
                obj['ReleaseTimeOverlapped'] = info.u.disk.IdentifyData.ReleaseTimeOverlapped
                obj['ReleaseTimeServiceCommand'] = info.u.disk.IdentifyData.ReleaseTimeServiceCommand
                obj['MajorRevision'] = info.u.disk.IdentifyData.MajorRevision
                obj['MinorRevision'] = info.u.disk.IdentifyData.MinorRevision

                obj['TotalFree'] = info.u.disk.TotalFree * 512
                obj['MaxFree'] = info.u.disk.MaxFree * 512
                obj['BadSectors'] = info.u.disk.BadSectors
                obj['ParentArrays'] = arrayToList(info.u.disk.ParentArrays)

                data = obj

                ret = get_error_result("Success", data)

            return JSONResponse(ret)
        
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("getPhysicalDiskInfoError")

            JSONResponse(resp)


def getAllPhysicalDiskList():
    
    data = []

    try:
        disks = (ctypes.c_uint32 * DEVICE_MAX_COUNT)()
        actuallyDeviceCnt = vrcGetPhysicalDevices(disks, DEVICE_MAX_COUNT)

        logger.debug('总共 ' + str(actuallyDeviceCnt) + ' 物理磁盘')

        info = VRC_DEVICE_INFO()#class
        if actuallyDeviceCnt > 0:
            for i in disks:#设备id
                if i == 0:#设备id不为0
                    break

                if vrcGetDeviceInfo(i, ctypes.byref(info)) != 0:#传入info指针
                    logger.debug('获取设备id为： ' + str(i) + ' 的物理磁盘信息失败！！！')
                    continue
        
                else:
                        printDeviceInfo(i, info)
                        obj = {}
                        obj['id'] = i
                        obj['dwSize'] = info.dwSize
                        obj['revision'] = info.revision

                        obj['Type'] = info.Type
                        obj['CachePolicy'] = info.CachePolicy
                        obj['VBusId'] = info.VBusId
                        obj['TargetId'] = info.TargetId
                        obj['Capacity'] = info.Capacity * 512
                        obj['ParentArray'] = info.ParentArray
                        
                        obj['ControllerId'] = info.u.disk.ControllerId + 1
                        obj['PathId'] = info.u.disk.PathId + 1
                        obj['TargetId'] = info.u.disk.TargetId
                        obj['DeviceModeSetting'] = info.u.disk.DeviceModeSetting
                        obj['DeviceType'] = info.u.disk.DeviceType
                        obj['UsableMode'] = info.u.disk.UsableMode
                        
                        if sys.byteorder == 'big':#大端模式下，注意位域
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x80 > 0: obj['ReadAheadSupported'] = 1 
                            else: obj['ReadAheadSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x40 > 0: obj['ReadAheadEnabled'] = 1
                            else: obj['ReadAheadEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x20 > 0: obj['WriteCacheSupported'] = 1
                            else: obj['WriteCacheSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x10 > 0: obj['WriteCacheEnabled'] = 1
                            else: obj['WriteCacheEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x08 > 0: obj['TCQSupported'] = 1
                            else: obj['TCQSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x04 > 0: obj['TCQEnabled'] = 1
                            else: obj['TCQEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x02 > 0: obj['NCQSupported'] = 1
                            else: obj['NCQSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x01 > 0: obj['NCQEnabled'] = 1
                            else: obj['NCQEnabled'] = 0

                            obj['SpinUpMode'] = (info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0xc0) >> 6
                            if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x20 > 0: obj['SMARTSupported'] = 1
                            else: obj['SMARTSupported'] = 0
                            if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x10 > 0: obj['SMARTEnabled'] = 1
                            else: obj['SMARTEnabled'] = 0
                            obj['SectorSizeShift'] = info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x0F
                        
                        else:
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x80 > 0: obj['NCQEnabled'] = 1 
                            else: obj['NCQEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x40 > 0: obj['NCQSupported'] = 1
                            else: obj['NCQSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x20 > 0: obj['TCQEnabled'] = 1
                            else: obj['TCQEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x10 > 0: obj['TCQSupported'] = 1
                            else: obj['TCQSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x08 > 0: obj['WriteCacheEnabled'] = 1
                            else: obj['WriteCacheEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x04 > 0: obj['WriteCacheSupported'] = 1
                            else: obj['WriteCacheSupported'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x02 > 0: obj['ReadAheadEnabled'] = 1
                            else: obj['ReadAheadEnabled'] = 0
                            if info.u.disk.ReadWrite_TCQ_NCQ_Support_Enable & 0x01 > 0: obj['ReadAheadSupported'] = 1
                            else: obj['ReadAheadSupported'] = 0

                            obj['SectorSizeShift'] = (info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0xF0) >> 4
                            if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x08 > 0: obj['SMARTEnabled'] = 1
                            else: obj['SMARTEnabled'] = 0
                            if info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x04 > 0: obj['SMARTSupported'] = 1
                            else: obj['SMARTSupported'] = 0
                            obj['SpinUpMode'] = info.u.disk.SpinUpMode_SMART_SectorSizeShift & 0x03

                        flagCnt = 0
                        flagString = ''
                        for id in info.u.disk.ParentArrays:
                            if id != 0:
                                deviceInfo = VRC_DEVICE_INFO()#class
                                if vrcGetDeviceInfo(id, ctypes.byref(deviceInfo)) != 0:#传入deviceInfo指针
                                    logger.debug('获取父设备id为： ' + str(id) + ' 的设备信息失败！！！')
                                    continue
                                else:
                                    if deviceInfo.Type == DEVTYPE_ARRAY:
                                        if len(flagString) == 0:
                                            flagString = flagString + '磁盘阵列'
                                        flagString = flagString + '(' + bytes(deviceInfo.u.array.Name).decode('utf-8').replace('\u0000', '') + ')'
                        if len(flagString) != 0:
                            flagString = flagString + ', '

                        if info.u.disk.Flags & DISK_FLAG_DISABLED:
                            flagString = flagString + "磁盘离线 "
                            insertHardRaidErrorTable(f'槽位号为：{obj["PathId"]}的物理磁盘失效')
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_BOOTDISK:
                            flagString = flagString + "磁盘有一个活动分区 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_BOOTMARK:
                            flagString = flagString + "磁盘已设置启动标记 "
                            flagCnt = flagCnt + 1
                        if (info.u.disk.Flags & DISK_FLAG_SATA) and (info.u.disk.Flags & DISK_FLAG_SAS) == 0:
                            flagString = flagString + "SATA磁盘 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_ON_PM_PORT:
                            flagString = flagString + "PM端口 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_SAS:
                            flagString = flagString + "SAS磁盘 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_IN_ENCLOSURE:
                            flagString = flagString + "磁盘在expander上 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_UNINITIALIZED:
                            flagString = flagString + "磁盘未初始化 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_LEGACY:
                            flagString = flagString + "磁盘为legacy设备 "
                            flagCnt = flagCnt + 1
                        if info.u.disk.Flags & DISK_FLAG_IS_SPARE:
                            flagString = flagString + "磁盘为备用盘 "
                            flagCnt = flagCnt + 1
                        if flagCnt == 0:
                            flagString = flagString + "未知"

                        obj['Flags'] = flagString
                        if obj['Flags'].find('磁盘未初始化') != -1:
                            insertHardRaidErrorTable('所在槽位号:' + str(obj["PathId"]) + ' 的物理磁盘未初始化')

                        obj['GeneralConfiguration'] = info.u.disk.IdentifyData.GeneralConfiguration
                        obj['NumberOfCylinders'] = info.u.disk.IdentifyData.NumberOfCylinders
                        obj['Reserved1'] = info.u.disk.IdentifyData.Reserved1
                        obj['NumberOfHeads'] = info.u.disk.IdentifyData.NumberOfHeads
                        obj['UnformattedBytesPerTrack'] = info.u.disk.IdentifyData.UnformattedBytesPerTrack
                        obj['UnformattedBytesPerSector'] = info.u.disk.IdentifyData.UnformattedBytesPerSector
                        obj['SectorsPerTrack'] = info.u.disk.IdentifyData.SectorsPerTrack
                        obj['VendorUnique1'] = arrayToList(info.u.disk.IdentifyData.VendorUnique1)

                        SerialNumberString = ''
                        for i in range(10):
                            SerialNumberString = SerialNumberString + chr((info.u.disk.IdentifyData.SerialNumber[i] & 0xFF00) >> 8)#将ascii码转换成字符
                            SerialNumberString = SerialNumberString + chr(info.u.disk.IdentifyData.SerialNumber[i] & 0xFF)#将ascii码转换成字符
                        obj['SerialNumber'] = SerialNumberString.replace(' ','')

                        obj['BufferType'] = info.u.disk.IdentifyData.BufferType
                        obj['BufferSectorSize'] = info.u.disk.IdentifyData.BufferSectorSize
                        obj['NumberOfEccBytes'] = info.u.disk.IdentifyData.NumberOfEccBytes

                        hardVersionString = ''
                        for i in range(4):
                            hardVersionString = hardVersionString + chr((info.u.disk.IdentifyData.FirmwareRevision[i] & 0xFF00) >> 8)#将ascii码转换成字符
                            hardVersionString = hardVersionString + chr(info.u.disk.IdentifyData.FirmwareRevision[i] & 0xFF)#将ascii码转换成字符
                        obj['FirmwareRevision'] = hardVersionString

                        obj['ModelNumber'] = bytes(info.u.disk.IdentifyData.ModelNumber).decode('utf-8').replace('\u0000', '')
                        obj['MaximumBlockTransfer'] = info.u.disk.IdentifyData.MaximumBlockTransfer
                        obj['VendorUnique2'] = info.u.disk.IdentifyData.VendorUnique2
                        obj['DoubleWordIo'] = info.u.disk.IdentifyData.DoubleWordIo
                        obj['Capabilities'] = info.u.disk.IdentifyData.Capabilities
                        obj['Reserved2'] = info.u.disk.IdentifyData.Reserved2
                        obj['VendorUnique3'] = info.u.disk.IdentifyData.VendorUnique3
                        obj['PioCycleTimingMode'] = info.u.disk.IdentifyData.PioCycleTimingMode
                        obj['VendorUnique4'] = info.u.disk.IdentifyData.VendorUnique4
                        obj['DmaCycleTimingMode'] = info.u.disk.IdentifyData.DmaCycleTimingMode
                        obj['TranslationFieldsValid'] = info.u.disk.IdentifyData.TranslationFieldsValid
                        obj['NumberOfCurrentCylinders'] = info.u.disk.IdentifyData.NumberOfCurrentCylinders
                        obj['NumberOfCurrentHeads'] = info.u.disk.IdentifyData.NumberOfCurrentHeads
                        obj['CurrentSectorsPerTrack'] = info.u.disk.IdentifyData.CurrentSectorsPerTrack
                        obj['CurrentSectorCapacity'] = info.u.disk.IdentifyData.CurrentSectorCapacity
                        obj['CurrentMultiSectorSetting'] = info.u.disk.IdentifyData.CurrentMultiSectorSetting
                        obj['UserAddressableSectors'] = info.u.disk.IdentifyData.UserAddressableSectors
                        obj['SingleWordDMASupport'] = info.u.disk.IdentifyData.SingleWordDMASupport
                        obj['SingleWordDMAActive'] = info.u.disk.IdentifyData.SingleWordDMAActive
                        obj['MultiWordDMASupport'] = info.u.disk.IdentifyData.MultiWordDMASupport
                        obj['MultiWordDMAActive'] = info.u.disk.IdentifyData.MultiWordDMAActive
                        obj['AdvancedPIOModes'] = info.u.disk.IdentifyData.AdvancedPIOModes
                        obj['Reserved4'] = info.u.disk.IdentifyData.Reserved4
                        obj['MinimumMWXferCycleTime'] = info.u.disk.IdentifyData.MinimumMWXferCycleTime
                        obj['RecommendedMWXferCycleTime'] = info.u.disk.IdentifyData.RecommendedMWXferCycleTime
                        obj['MinimumPIOCycleTime'] = info.u.disk.IdentifyData.MinimumPIOCycleTime
                        obj['MinimumPIOCycleTimeIORDY'] = info.u.disk.IdentifyData.MinimumPIOCycleTimeIORDY
                        obj['ReleaseTimeOverlapped'] = info.u.disk.IdentifyData.ReleaseTimeOverlapped
                        obj['ReleaseTimeServiceCommand'] = info.u.disk.IdentifyData.ReleaseTimeServiceCommand
                        obj['MajorRevision'] = info.u.disk.IdentifyData.MajorRevision
                        obj['MinorRevision'] = info.u.disk.IdentifyData.MinorRevision

                        obj['TotalFree'] = info.u.disk.TotalFree * 512
                        obj['MaxFree'] = info.u.disk.MaxFree * 512
                        obj['BadSectors'] = info.u.disk.BadSectors
                        obj['ParentArrays'] = arrayToList(info.u.disk.ParentArrays)

                        data.append(obj)
   
    except Exception as e:
            logger.error(''.join(traceback.format_exc()))
    
    return data

class getPhysicalDisks(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []

        try:

            data = getAllPhysicalDiskList()

            ret = get_error_result("Success", data)

            return JSONResponse(ret)
        
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("getPhysicalDiskInfoError")

            JSONResponse(resp)


class getSpecificLogicDisks(APIView):
    
    def post(self, request, *args, **kwargs):

        id = request.data.get('id')
        ret = {}
        data = {}
        
        try:

            info = VRC_DEVICE_INFO()#class

            if vrcGetDeviceInfo(id, ctypes.byref(info)) != 0:#传入info指针
                logger.debug('获取设备id为： ' + str(id) + ' 的逻辑盘信息失败！！！')
                ret['code'] = -2
                ret['msg'] = '获取逻辑磁盘信息失败'
                ret['data'] = data
                
            else:
                printDeviceInfo(id, info)
                obj = {}
                obj['id'] = id
                obj['dwSize'] = info.dwSize
                obj['revision'] = info.revision

                obj['Type'] = info.Type
                obj['CachePolicy'] = info.CachePolicy
                obj['VBusId'] = info.VBusId
                obj['TargetId'] = info.TargetId
                obj['Capacity'] = info.Capacity * 512
                obj['ParentArray'] = info.ParentArray

                obj['Name'] = bytes(info.u.array.Name).decode('utf-8').replace('\u0000', '')
                obj['CreateTime'] = info.u.array.CreateTime

                if info.u.array.ArrayType == ARRAY_TYPE_RAID0:
                    if info.u.array.SubArrayType == ARRAY_TYPE_RAID1:
                        obj['ArrayType'] = 'RAID10 阵列'
                    elif info.u.array.SubArrayType == ARRAY_TYPE_RAID5:
                        obj['ArrayType'] = 'RAID50 阵列'
                    else:
                        obj['ArrayType'] = 'RAID0 阵列'
                elif info.u.array.ArrayType == ARRAY_TYPE_RAID1:
                    obj['ArrayType'] = 'RAID1 阵列'
                elif info.u.array.ArrayType == ARRAY_TYPE_RAID5:
                    obj['ArrayType'] = 'RAID5 阵列'
                elif info.u.array.ArrayType == ARRAY_TYPE_RAID6:
                    obj['ArrayType'] = 'RAID6 阵列'
                elif info.u.array.ArrayType == ARRAY_TYPE_JBOD:
                    obj['ArrayType'] = 'JBOD 阵列'
                else:
                    obj['ArrayType'] = '未知'

                obj['BlockSizeShift'] = (2 << info.u.array.BlockSizeShift) / 2 * 512
                obj['nDisk'] = info.u.array.nDisk

                if info.u.array.SubArrayType == ARRAY_TYPE_RAID0:
                    obj['SubArrayType'] = 'RAID0 阵列（或 RAID10 阵列）'
                elif info.u.array.SubArrayType == ARRAY_TYPE_RAID1:
                    obj['SubArrayType'] = 'RAID1 阵列'
                elif info.u.array.SubArrayType == ARRAY_TYPE_RAID5:
                    obj['SubArrayType'] = 'RAID5 阵列'
                elif info.u.array.SubArrayType == ARRAY_TYPE_JBOD:
                    obj['SubArrayType'] = 'JBOD 阵列'
                else:
                    obj['SubArrayType'] = '未知'

                arrayFlag = 0
                currentTask = -1
                flagString = ''
                if info.u.array.Flags & ARRAY_FLAG_DISABLED:
                    flagString = flagString + '阵列离线 '
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_NEEDBUILDING:
                    flagString = flagString + '阵列重建未完成 '
                    currentTask = 1
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_REBUILDING:
                    flagString = flagString + '阵列正在重建 '
                    currentTask = 1
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_BROKEN:
                    flagString = flagString + '阵列缺少磁盘 '
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_VERIFYING:
                        flagString = flagString + '阵列正在校验 '
                        currentTask = 2
                        arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_INITIALIZING:
                    flagString = flagString + '阵列正在初始化 '
                    currentTask = 3
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_NEEDTRANSFORM:
                    flagString = flagString + '阵列等待转换级别 '
                    currentTask = 4
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_TRANSFORMING:
                    flagString = flagString + '阵列正在转换级别 '
                    currentTask = 4
                    arrayFlag = arrayFlag + 1
                if info.u.array.Flags & ARRAY_FLAG_NEEDINITIALIZING:
                    flagString = flagString + '阵列初始化未完成 '
                    currentTask = 3
                    arrayFlag = arrayFlag + 1
                if arrayFlag == 0:
                    flagString = flagString + '正常'
                
                if currentTask == 1:#重建中
                    flagString = flagString + ' ' + str(info.u.array.RebuildingProgress / 100.0) + '%'
                elif currentTask == 2:#校验中
                    flagString = flagString + ' ' + str(info.u.array.RebuildingProgress / 100.0) + '%'
                elif currentTask == 3:#初始化中
                    flagString = flagString + ' ' + str(info.u.array.RebuildingProgress / 100.0) + '%'
                elif currentTask == 4:#转化中
                    flagString = flagString + ' ' + str(info.u.array.TransformingProgress / 100.0) + '%'
                else:
                    flagString = flagString
                obj['Flags'] = flagString

                obj['RebuildingProgress'] = info.u.array.RebuildingProgress / 100
                obj['TransformingProgress'] = info.u.array.TransformingProgress / 100
                obj['RebuiltSectors'] = info.u.array.RebuiltSectors
                obj['TransformSource'] = info.u.array.TransformSource
                obj['TransformTarget'] = info.u.array.TransformTarget
                obj['Signature'] = info.u.array.Signature
                obj['SectorSizeShift'] = (2 << info.u.array.SectorSizeShift) / 2 * 512 
                obj['Critical_Members'] = info.u.array.Critical_Members
                obj['Members'] = arrayToList(info.u.array.Members)

                data = obj

                ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("getLogicDiskInfoError")

            JSONResponse(resp)
        


class getLogicDisks(APIView):
    
    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            disks = (ctypes.c_uint32 * DEVICE_MAX_COUNT)()
            actuallyDeviceCnt = vrcGetLogicalDevices(disks, DEVICE_MAX_COUNT)

            logger.debug('总共 ' + str(actuallyDeviceCnt) + ' 逻辑盘')

            info = VRC_DEVICE_INFO()#class
            if actuallyDeviceCnt > 0:
                for i in disks:#设备id
                    if i == 0:#设备id不为0
                        break

                    if vrcGetDeviceInfo(i, ctypes.byref(info)) != 0:#传入info指针
                        logger.debug('获取设备id为： ' + str(i) + ' 的逻辑盘信息失败！！！')
                        continue
                    else:
                        printDeviceInfo(i, info)
                        obj = {}
                        obj['id'] = i
                        obj['dwSize'] = info.dwSize
                        obj['revision'] = info.revision

                        obj['Type'] = info.Type
                        obj['CachePolicy'] = info.CachePolicy
                        obj['VBusId'] = info.VBusId
                        obj['TargetId'] = info.TargetId
                        obj['Capacity'] = info.Capacity * 512
                        obj['ParentArray'] = info.ParentArray

                        if info.Type == DEVTYPE_ARRAY:
                            obj['Name'] =  bytes(info.u.array.Name).decode('utf-8').replace('\u0000', '')
                            obj['CreateTime'] = info.u.array.CreateTime

                            if info.u.array.ArrayType == ARRAY_TYPE_RAID0:
                                if info.u.array.SubArrayType == ARRAY_TYPE_RAID1:
                                    obj['ArrayType'] = 'RAID10 阵列'
                                elif info.u.array.SubArrayType == ARRAY_TYPE_RAID5:
                                    obj['ArrayType'] = 'RAID50 阵列'
                                else:
                                    obj['ArrayType'] = 'RAID0 阵列'
                            elif info.u.array.ArrayType == ARRAY_TYPE_RAID1:
                                obj['ArrayType'] = 'RAID1 阵列'
                            elif info.u.array.ArrayType == ARRAY_TYPE_RAID5:
                                obj['ArrayType'] = 'RAID5 阵列'
                            elif info.u.array.ArrayType == ARRAY_TYPE_RAID6:
                                obj['ArrayType'] = 'RAID6 阵列'
                            elif info.u.array.ArrayType == ARRAY_TYPE_JBOD:
                                obj['ArrayType'] = 'JBOD 阵列'
                            else:
                                obj['ArrayType'] = '未知'
    
                            obj['BlockSizeShift'] = (2 << info.u.array.BlockSizeShift) / 2 * 512
                            obj['nDisk'] = info.u.array.nDisk

                            if info.u.array.SubArrayType == ARRAY_TYPE_RAID0:
                                obj['SubArrayType'] = 'RAID0 阵列（或 RAID10 阵列）'
                            elif info.u.array.SubArrayType == ARRAY_TYPE_RAID1:
                                obj['SubArrayType'] = 'RAID1 阵列'
                            elif info.u.array.SubArrayType == ARRAY_TYPE_RAID5:
                                obj['SubArrayType'] = 'RAID5 阵列'
                            elif info.u.array.SubArrayType == ARRAY_TYPE_JBOD:
                                obj['SubArrayType'] = 'JBOD 阵列'
                            else:
                                obj['SubArrayType'] = '未知'

                            arrayFlag = 0
                            currentTask = -1
                            flagString = ''
                            if info.u.array.Flags & ARRAY_FLAG_DISABLED:
                                flagString = flagString + '阵列离线 '
                                insertHardRaidErrorTable(f'{obj["Name"]} 阵列失效')
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_NEEDBUILDING:
                                flagString = flagString + '阵列重建未完成 '
                                currentTask = 1
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_REBUILDING:
                                flagString = flagString + '阵列正在重建 '
                                currentTask = 1
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_BROKEN:
                                flagString = flagString + '阵列缺少磁盘 '
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_VERIFYING:
                                flagString = flagString + '阵列正在校验 '
                                currentTask = 2
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_INITIALIZING:
                                flagString = flagString + '阵列正在初始化 '
                                currentTask = 3
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_NEEDTRANSFORM:
                                flagString = flagString + '阵列等待转换级别 '
                                currentTask = 4
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_TRANSFORMING:
                                flagString = flagString + '阵列正在转换级别 '
                                currentTask = 4
                                arrayFlag = arrayFlag + 1
                            if info.u.array.Flags & ARRAY_FLAG_NEEDINITIALIZING:
                                flagString = flagString + '阵列初始化未完成 '
                                currentTask = 3
                                arrayFlag = arrayFlag + 1
                            if arrayFlag == 0:
                                flagString = flagString + '正常'
                            
                            if currentTask == 1:#重建中
                                flagString = flagString + ' ' + str(info.u.array.RebuildingProgress / 100.0) + '%'
                            elif currentTask == 2:#校验中
                                flagString = flagString + ' ' + str(info.u.array.RebuildingProgress / 100.0) + '%'
                            elif currentTask == 3:#初始化中
                                flagString = flagString + ' ' + str(info.u.array.RebuildingProgress / 100.0) + '%'
                            elif currentTask == 4:#转化中
                                flagString = flagString + ' ' + str(info.u.array.TransformingProgress / 100.0) + '%'
                            else:
                                flagString = flagString
                            obj['Flags'] = flagString

                            obj['RebuildingProgress'] = info.u.array.RebuildingProgress / 100
                            obj['TransformingProgress'] = info.u.array.TransformingProgress / 100
                            obj['RebuiltSectors'] = info.u.array.RebuiltSectors
                            obj['TransformSource'] = info.u.array.TransformSource
                            obj['TransformTarget'] = info.u.array.TransformTarget
                            obj['Signature'] = info.u.array.Signature
                            obj['SectorSizeShift'] = (2 << info.u.array.SectorSizeShift) / 2 * 512 
                            obj['Critical_Members'] = info.u.array.Critical_Members
                            obj['Members'] = arrayToList(info.u.array.Members)
                        else:
                            obj['Name'] =  '[' + str(info.u.disk.PathId) + '] ' + bytes(info.u.disk.IdentifyData.ModelNumber).decode('utf-8').replace('\u0000', '')
                            obj['CreateTime'] = ''
                            obj['ArrayType'] = 'legacy'
                            obj['Flags'] = 'legacy'
                            obj['RebuildingProgress'] = 100
                            obj['TransformingProgress'] = 100
                            obj['RebuiltSectors'] = ''
                            obj['TransformSource'] = ''
                            obj['TransformTarget'] = ''
                            obj['Signature'] = ''
                            obj['SectorSizeShift'] = ''
                            obj['Critical_Members'] = ''
                            obj['Members'] = []

                        data.append(obj)

            ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("getLogicDiskInfoError")

            JSONResponse(resp)
        

class calcMaxArrayCapacity(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = {}
        
        try:
            logger.debug(request.data)

            id = request.data.get('id')
            SubDisks = request.data.get('subDisks')
            SectorSizeShift = request.data.get('sectorSize')
            ArrayType = request.data.get('level')
            nDisk = request.data.get('nDisk')
            BlockSizeShift = request.data.get('blockSize')
            CreateFlags = request.data.get('init_cache_mode')
            Name = request.data.get('name')#string
            CreateTime = int(datetime.now().timestamp())
            Capacity =  request.data.get('capacity')
            Members = request.data.get('memberDiskId')#list

            para = VRC_CREATE_ARRAY_PARAMS()
            para.dwSize = 380 #fixed
            para.revision = 0 #fixed
            para.SubDisks = SubDisks
            para.SectorSizeShift = SectorSizeShift
            para.ArrayType = ArrayType
            para.nDisk = nDisk
            para.BlockSizeShift = BlockSizeShift
            para.CreateFlags = CreateFlags

            listName = list(Name)#将string转换成list
            for index in range(len(listName)):#list 转换成 array
                para.ArrayName[index] = ord(listName[index])#将字符转换成ascii

            para.CreateTime = CreateTime
            para.Capacity = Capacity

            for index in range(len(Members)):#list 转换成 array
                para.Members[index] = Members[index]

            print_VRC_CREATE_ARRAY_PARAMS(para)
            capacity = ctypes.c_uint64()

            theArrayId = ctypes.c_uint32(id)

            if(vrcCalcMaxArrayCapacity(theArrayId, ctypes.byref(para), ctypes.byref(capacity)) != 0):
   
                ret = get_error_result("GetMaxFreeMemoryError")

            else:
                obj = {}
                obj['maxFreeCapacity'] = capacity.value

                ret = get_error_result("Success", obj)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("CalcMaxArrayCapacityError")
            JSONResponse(resp)


class createHardRaid(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            logger.debug(request.data)

            SubDisks = request.data.get('subDisks')
            SectorSizeShift = request.data.get('sectorSize')
            ArrayType = request.data.get('level')
            nDisk = request.data.get('nDisk')
            BlockSizeShift = request.data.get('blockSize')
            CreateFlags = request.data.get('init_cache_mode')
            Name = request.data.get('name')#string
            CreateTime = int(datetime.now().timestamp())
            Capacity =  request.data.get('capacity')
            Members = request.data.get('memberDiskId')#list

            para = VRC_CREATE_ARRAY_PARAMS()
            para.dwSize = 380 #fixed
            para.revision = 0 #fixed
            para.SubDisks = SubDisks
            para.SectorSizeShift = SectorSizeShift
            para.ArrayType = ArrayType
            para.nDisk = nDisk
            para.BlockSizeShift = BlockSizeShift
            para.CreateFlags = CreateFlags

            listName = list(Name)#将string转换成list
            for index in range(len(listName)):#list 转换成 array
                para.ArrayName[index] = ord(listName[index])#将字符转换成ascii

            para.CreateTime = CreateTime
            para.Capacity = Capacity

            for index in range(len(Members)):#list 转换成 array
                para.Members[index] = Members[index]

            print_VRC_CREATE_ARRAY_PARAMS(para)

            if(vrcCreateArray(ctypes.byref(para)) == 0):
                ret = get_error_result("createHardRaidError")

            else:
                ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("createHardRaidError")

            JSONResponse(resp)



#获取/dev/下的磁盘名字
def getDevDisk():
    
    devDiskNameList = []
    allLines = os.popen('lsblk -pS -o NAME |awk \'NR!=1{print $0}\'', 'r').readlines()
    
    for ele in allLines:
        devDiskNameList.append(ele.split('\n')[0])

    return devDiskNameList

SCSI_IOCTL_GET_IDLUN = 0x5382

class SCSI_ID(ctypes.Structure):

    _pack_ = 1

    _fields_ = [
        ("four_in_one", ctypes.c_uint32),
        ("host_unique_id", ctypes.c_uint32),
    ]


def getTheRaidDevDisk(devDiskList, VBusId, TargetId):

    theDevDisk = ''

    for ele in devDiskList:

        argid = SCSI_ID()
        fd = os.open(ele, os.O_RDWR)
        if fd < 0:
            return theDevDisk

        if fcntl.ioctl(fd, SCSI_IOCTL_GET_IDLUN, argid) < 0:
            return theDevDisk
        
        logger.debug(argid.four_in_one)
        logger.debug(argid.host_unique_id)
        os.close(fd)

        ID = argid.four_in_one & 0xFF
        Host = (argid.four_in_one >> 24) & 0xFF
        logger.debug(f'ID:{ID}, host:{Host}')

        if Host == int(VBusId) and ID == int(TargetId):
            theDevDisk = ele
            return theDevDisk

    return theDevDisk


from web_manage.hardware.raid.views import PvsDev 
class deleteHardRaid(APIView):

     def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            logger.debug(request.data)
            id = request.data.get('id')
            method = request.data.get('method')

            devDiskNameList = getDevDisk()
            logger.debug(f'/dev/下的磁盘：{devDiskNameList}')

            info = VRC_DEVICE_INFO()#class

            VBusId = ''
            TargetId = ''

            if vrcGetDeviceInfo(id, ctypes.byref(info)) != 0:#传入info指针
                logger.debug('获取设备id为： ' + str(id) + ' 的逻辑盘信息失败！！！')
                ret = get_error_result("DeleteHardRaidError")
                return JSONResponse(ret)
                
            else:
                #printDeviceInfo(id, info)

                VBusId = info.VBusId
                TargetId = info.TargetId

            if VBusId == '' or TargetId == '':
                logger.debug('获取设备id为： ' + str(id) + ' 的逻辑盘信息失败！！！')
                ret = get_error_result("DeleteHardRaidError")
                return JSONResponse(ret)
            logger.debug(f'VBusId={VBusId}, TargetId={TargetId}')

            theDevDisk = getTheRaidDevDisk(devDiskNameList, VBusId, TargetId)
            if theDevDisk == '':
                logger.debug('查找该删除raid对应的/dev/设备失败！！！')
                ret = get_error_result("DeleteHardRaidError")
                return JSONResponse(ret)

            theRaidDevHaveUsed = False
            pysicalVolumeDev = PvsDev()
            for ele in pysicalVolumeDev:
                if ele.find(theDevDisk) != -1:
                    theRaidDevHaveUsed = True
                    break

            if theRaidDevHaveUsed:
                ret = get_error_result("HardRaidHaveUsedError")
                return JSONResponse(ret)

            if vrcDeleteArray(id, method) != 0:
                ret = get_error_result("DeleteHardRaidError")

            else:
                ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("DeleteHardRaidError")

            JSONResponse(resp)



class secureDeleteHardRaid(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            logger.debug(request.data)
            id = ctypes.c_uint32(request.data.get('id'))
            id1 = ctypes.c_uint32(request.data.get('id'))

            if vrcQueryRemove(1, ctypes.byref(id)) != 0:
                ret = get_error_result("ArrayCannotSafelyRemoved")

            else:
                
                if vrcRemoveDevices(1, ctypes.byref(id1)) != 0:
                    ret = get_error_result("SecureDeleteHardRaidError")
                
                else:
                    ret = get_error_result("Success", data)

            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("SecureDeleteHardRaidError")
  
            JSONResponse(resp)


class reScan(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []

        
        try:
            if vrcRescanDevices() != 0:
                    ret = get_error_result("reScanError")
                
            else:
                ret = get_error_result("Success", data)

            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("reScanError")
   
            JSONResponse(resp)


class checkData(APIView):

    def post(self, request, *args, **kwargs):

        ids = request.data.get('id')# 类型为整数列表
        state = request.data.get('state')
        ret = {}
        data = []
        
        try:

            msg = ''
            checkDataOk = True
            for arrayId in ids:
                logger.debug(datetime.now())
                if vrcSetArrayState(arrayId, state) != 0:
                        checkDataOk = False
                        if len(ids) > 1:#raid10 或者 raid50
                            msg = msg + '子阵列: ' + str(arrayId) + ' 校验失败；'
                        else:
                            msg = msg + '阵列: ' + str(arrayId) + ' 校验失败；'
                logger.debug(datetime.now())
                

            if checkDataOk == False:
                ret = get_error_result("ArrayCheckDataError", data)

            else:
                ret = get_error_result("Success", data)

            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("ArrayCheckDataError")
    
            JSONResponse(resp)


class setArrayState(APIView):

    def post(self, request, *args, **kwargs):

        ids = request.data.get('id')# 类型为整数列表
        state = request.data.get('state')
        ret = {}
        data = []
        
        try:
            msg = ''
            checkDataOk = True
            for arrayId in ids:
                logger.debug(datetime.now())
                if vrcSetArrayState(arrayId, state) != 0:
                        checkDataOk = False
                        if len(ids) > 1:#raid10 或者 raid50
                            msg = msg + '子阵列: ' + str(arrayId) + ' 设置状态失败；'
                        else:
                            msg = msg + '阵列: ' + str(arrayId) + ' 设置状态失败；'
                logger.debug(datetime.now())
                

            if checkDataOk == False:
                ret = get_error_result("SetArrayStateError", data)

            else:
                ret = get_error_result("Success", data)

            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("SetArrayStateError")
     
            JSONResponse(resp)


class setArrayPara(APIView):

    def post(self, request, *args, **kwargs):

        id = request.data.get('id')#int
        targetType = request.data.get('targetType')#int
        infoType = request.data.get('infoType')#int
        para =  request.data.get('para')#string

        ret = {}
        data = []
        
        try:

            paraLen = 0
            info = SET_VDEV_INFO()
            info.target_type = targetType
            info.infor_type = infoType
            
            if infoType == AIT_NAME:#修改名字
                chrLits = list(para)
                listLen = len(chrLits)
                paraLen = 16#固定16

                if listLen > paraLen:
                    listLen = paraLen

                for index in range(listLen):
                    info.param[index] = ord(chrLits[index])#将字符转变成unicode编码
                for index in range(paraLen - listLen):
                    info.param[listLen + index] = ord('\0')#填充空余空字符，将字符转变成unicode编码

            else:#修改缓存模式、设置磁盘的:预读、写缓存、NCQ、SMART 使能状态
                info.param[0] = int(para)
                paraLen = 1

            info.param_length = paraLen

            print_SET_VDEV_INFO(info)
            if vrcSetVdevInfo(id, ctypes.byref(info)) != 0:
                    ret = get_error_result("SetArrayParaError")
                
            else:
                ret = get_error_result("Success", data)

            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("SetArrayParaError")
         
            JSONResponse(resp)


class transform(APIView):

    def post(self, request, *args, **kwargs):

        id = request.data.get('sourId')#int
        SubDisks = request.data.get('subDisks')
        SectorSizeShift = request.data.get('sectorSize')
        ArrayType = request.data.get('level')
        nDisk = request.data.get('nDisk')
        BlockSizeShift = request.data.get('blockSize')
        CreateFlags = request.data.get('init_cache_mode')
        Name = request.data.get('name')#string
        CreateTime = int(datetime.now().timestamp())
        Capacity =  request.data.get('capacity')
        Members = request.data.get('memberDiskId')#list

        ret = {}
        data = []
        
        try:
        
            para = VRC_CREATE_ARRAY_PARAMS()

            para.dwSize = 380 #fixed
            para.revision = 0 #fixed
            para.SubDisks = SubDisks
            para.SectorSizeShift = SectorSizeShift
            para.ArrayType = ArrayType
            para.nDisk = nDisk
            para.BlockSizeShift = BlockSizeShift
            para.CreateFlags = CreateFlags

            listName = list(Name)#将string转换成list
            for index in range(len(listName)):#list 转换成 array
                para.ArrayName[index] = ord(listName[index])#将字符转换成ascii

            para.CreateTime = CreateTime
            para.Capacity = Capacity

            for index in range(len(Members)):#list 转换成 array
                para.Members[index] = Members[index]

            if vrcCreateTransform(id, ctypes.byref(para)) == 0:
                ret = get_error_result("TransformArrayError")
                
            else:
                ret = get_error_result("Success", data)

            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("TransformArrayError")
       
            JSONResponse(resp)


class initDisk(APIView):
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'id':openapi.Schema(type=openapi.TYPE_INTEGER, description='id'),
        },
        required=['id'],
    ))

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            logger.debug(request.data)
            id = ctypes.c_uint32(request.data.get('id'))#int

            if vrcInitDisks(1, ctypes.byref(id)) != 0:
                ret = get_error_result("InitDiskError")

            else:
                ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("InitDiskError")
      
            JSONResponse(resp)


class initDiskList(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'idList':openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_INTEGER), description='id数组'),
        },
        required=['idList'],
    ))

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:

            ret = get_error_result("Success", data)

            logger.debug(request.data)
            idList = request.data.get('idList')#

            for id in idList:
                c_id = ctypes.c_uint32(id)
                if vrcInitDisks(1, ctypes.byref(c_id)) != 0:
                    kwargs = {
                        'detail' : f"初始化磁盘id为:{id}的磁盘失败"
                    }
                    ret = get_error_result("InitDiskListError", data=None, **kwargs)
                    break
                    
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("InitDiskError")
      
            JSONResponse(resp)


class addSpare(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            logger.debug(request.data)
            id = ctypes.c_uint32(request.data.get('id'))#int

            if vrcAddSpareDisk(id) != 0:
                ret = get_error_result("AddSpareDiskError")

            else:
                ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("AddSpareDiskError")
   
            JSONResponse(resp)
        

class removeSpare(APIView):

    def post(self, request, *args, **kwargs):

        ret = {}
        data = []
        
        try:
            logger.debug(request.data)
            id = ctypes.c_uint32(request.data.get('id'))#int 

            if vrcRemoveSpareDisk(id) != 0:
                ret = get_error_result("RemoveSpareDiskError")

            else:
                ret = get_error_result("Success", data)
            
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            insertHardRaidErrorTable(''.join(traceback.format_exc()))
            resp = get_error_result("RemoveSpareDiskError")

            JSONResponse(resp)




