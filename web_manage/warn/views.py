from enum import Enum
from web_manage.warn.models import warnRecord
from web_manage.warn.models import warnSet
from web_manage.warn.models import mails
from web_manage.warn.models import smtpSet
from web_manage.warn.models import warnQueryPositionRecord

import logging
import threading
import time

import smtplib
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from rest_framework.decorators import action
from web_manage.common import constants
from web_manage.common.utils import JSONResponse, WebPagination, Authentication, Permission, create_md5, \
    get_error_result, translateUTCOrLoaclTimeStringToLocalTime, TimeType
from web_manage.common.log import insert_operation_log

from rest_framework.views import APIView
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.shortcuts import HttpResponse
from django.utils import timezone
from uuid import uuid4
from rest_framework import status
from django.db.models import Q

from django.core.cache import cache
from django.http import Http404, HttpResponseServerError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import subprocess
import os
import traceback
import sqlite3
import datetime
from web_manage.common.cmdutils import run_cmd
from web_manage.hardware.models import LvInfo


logger = logging.getLogger(__name__)


def insertNewRecord(level, desc):
        """
        函数功能插入记录到warn表：

        level：该条记录告警级别，取值为正整数。
        desc  : 该条记录的描述
        """

        try:

            now = datetime.datetime.now()
            uuid = str(uuid4())

            record = {
                'uuid': uuid,
                'level':level,
                'time' : now,
                'desc' : desc,
                'hadNotified' :0
            }

            warnRecord.objects.create(**record)
        
        except:
            logger.error(''.join(traceback.format_exc()))
            raise



def selectWarnDateTableAndLevelConfig():

    status = True
    level = '0'
    leveSetTime = datetime.datetime.strptime('1990-1-1 00:00:00', "%Y-%m-%d %H:%M:%S")
    recordList = []

    try:
        warnRecordList = warnRecord.objects.all().order_by("-time")
        warnSetList = warnSet.objects.all()

        for ele in warnRecordList:
            record = []
            record.append(ele.uuid)
            record.append(ele.level)
            record.append(ele.time)
            record.append(ele.desc)
            record.append(ele.hadNotified)
            recordList.append(record)

        for ele in warnSetList:
            level = ele.warnLevel
            leveSetTime = ele.setTime
    

    except Exception as e:
        logger.error(''.join(traceback.format_exc()))
        status = False

    return status, level, leveSetTime, recordList


def selectMailDateTableAndSmtpServerConfig():

    status = True
    smtpServerAddr = ''
    smtpServerPort = ''
    smtpSendMail = ''
    smtpUser = ''
    smtpPasswd = ''

    recordList = []

    try:

        mailsList = mails.objects.all()
        smtpSetList = smtpSet.objects.all()

        for ele in mailsList:
            record = []
            record.append(ele.mail)
            recordList.append(record)

        for ele in smtpSetList:
            smtpServerAddr = ele.SMTPServer
            smtpServerPort = ele.SMTPPort
            smtpSendMail = ele.sendMail
            smtpUser = ele.SMTPUser
            smtpPasswd = ele.SMTPPasswd
    

    except Exception as e:
        logger.error(''.join(traceback.format_exc()))
        logger.debug('查询邮箱和smtp数据表失败!!!')
        status = False
        

    return status, smtpServerAddr, smtpServerPort, smtpSendMail, smtpUser, smtpPasswd, recordList

# hadNotifiedValue:0(未处理)  1:(已经邮箱发送)  2:(已经人工查阅)
def modifyNotifyColumn(uuidList, hadNotifiedValue):

    if len(uuidList) == 0:
        return

    try:
        for theUuid in  uuidList:
            print(theUuid)
            recordObj = warnRecord.objects.get(uuid=theUuid)
            recordObj.hadNotified = hadNotifiedValue
            recordObj.save()
            

    except Exception as e:

        logger.error(''.join(traceback.format_exc()))
        logger.debug('更新告警表失败！！！')


class warnInfoShowView(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'startDateTime': openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'endDateTime'  : openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'level': openapi.Schema(type=openapi.TYPE_INTEGER, description='告警级别'),
            'page': openapi.Schema(type=openapi.TYPE_INTEGER, description='第几页，从1开始'),
            'page_size': openapi.Schema(type=openapi.TYPE_INTEGER, description='每页最大记录数'),
        },
        required=['startDateTime', 'endDateTime', 'page', 'page_size'],
    ))    

    def post(self, request, *args, **kwargs):
        
        level = '0'
        leveSetTime = '1990-1-1 00:00:00'
        recordList = []

        try:
            startDateTime = request.data.get('startDateTime')
            endDateTime = request.data.get('endDateTime')
            queryLevel = request.data.get('level')
            queryLevel = int(queryLevel)

            start = translateUTCOrLoaclTimeStringToLocalTime(startDateTime, TimeType.UTC)
            end   = translateUTCOrLoaclTimeStringToLocalTime(endDateTime, TimeType.UTC)
            logger.debug(f'开始时间：{start}')
            logger.debug(f'结束时间：{end}')

            page = request.data.get('page')
            page_size = request.data.get('page_size')
            logger.debug(f'page:{page}, page_size:{page_size}')
            if page == None or page_size == None:
                page = 1
                page_size = 50#默认一页50条记录

            page = int(page)
            page_size = int(page_size)

            if page <= 0 or page_size <= 0:
                resp = get_error_result("QueryWranDatebaseOrLevelConfigError")
                return JSONResponse(resp)
           
            warnRecordList = warnRecord.objects.filter(time__gte=start, time__lte=end, level=queryLevel).order_by("-time")
            for ele in warnRecordList:
                record = []
                record.append(ele.uuid)
                record.append(ele.level)
                record.append(ele.time)
                record.append(ele.desc)
                record.append(ele.hadNotified)
                recordList.append(record)

            compete = int(len(recordList) / page_size)
            remain =  len(recordList) % page_size
            allPages = compete
            if remain > 0:
                allPages = compete + 1

            if allPages <= 0:
                recordList = []
            elif page < allPages:
                startPos = (page - 1) * page_size
                endPos = (page - 1) * page_size + page_size
                recordList = recordList[startPos : endPos]
            elif page >= allPages:

                page = allPages

                if page == compete:#都是整页
                    startPos = (page - 1) * page_size
                    endPos = (page - 1) * page_size + page_size
                    recordList = recordList[startPos : endPos]
                else:
                    startPos = (page - 1) * page_size
                    endPos = (page - 1) * page_size + remain
                    recordList = recordList[startPos : endPos]

            warnSetList = warnSet.objects.all()
            for ele in warnSetList:
                level = ele.warnLevel
                leveSetTime = ele.setTime
            
            obj = {}
            obj['page'] = page
            obj['page_size'] = page_size
            obj['allPage'] = allPages
            obj['warnLevelSetTime'] = leveSetTime
            obj['warnLevel'] = level
            obj['dataLibRecord'] = recordList
            ret = get_error_result("Success", obj)
            return JSONResponse(ret)

        except Exception as e:

            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("QueryWranDatebaseOrLevelConfigError")
            return JSONResponse(resp)


class setWarnLevel(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'warnLevel': openapi.Schema(type=openapi.TYPE_INTEGER),
        },
        required=['warnLevel'],
    ))
         
    def post(self, request, *args, **kwargs):
          
        logger.debug(request)
        warnLevel = request.data.get('warnLevel')
        now = datetime.datetime.now()
        logger.debug(now.strftime('%Y-%m-%d %H:%M:%S') + ' set warnLevel: ' + str(warnLevel))
  
        try:

            allRecord = warnSet.objects.all()
            for record in allRecord:
                record.delete()

            warnSet.objects.create(warnLevel=warnLevel, setTime=now)

            #insertNewRecord(5, "(仅测试)系统错误")#记得注释修改
            ret = get_error_result("Success")
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            data = {"code": -1, "msg": "设置告警级别出错", "data": ''}
            return JSONResponse(data)
    


#######################################邮箱###########################################

class getMailsAndSmtpServerInfo(APIView):

    def post(self, request, *args, **kwargs):

        status = True
        smtpServerAddr = ''
        smtpServerPort = ''
        smtpSendMail = ''
        smtpUser = ''
        smtpPasswd = ''
        recordList = []

        try:
            result = selectMailDateTableAndSmtpServerConfig()
            status = result[0]
            smtpServerAddr = result[1]
            smtpServerPort = result[2]
            smtpSendMail = result[3]
            smtpUser = result[4]
            smtpPasswd = result[5]
            recordList = result[6]

            if status == False:
                logger.debug('查询告警邮箱数据库和smtp服务器配置文件失败!!!')
                resp = get_error_result("QueryWarnMailOrSmtpConfigError")
                return JSONResponse(resp)
            
            obj = {}
            obj['smtpServerAddr'] = smtpServerAddr
            obj['smtpServerPort'] = smtpServerPort
            obj['smtpSendMail'] = smtpSendMail
            obj['smtpUser'] = smtpUser
            obj['smtpPasswd'] = smtpPasswd
            obj['dataLibRecord'] = recordList
            ret = get_error_result("Success", obj)
            return JSONResponse(ret)

        except Exception as e:

            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("QueryWarnMailOrSmtpConfigError")
            return JSONResponse(resp)


class setSmtpServerInfo(APIView):

    def post(self, request, *args, **kwargs):

        try:
            smtpServerName = request.data.get('smtpServerName')
            smtpServerPort = request.data.get('smtpServerPort')
            smtpSenderMail = request.data.get('smtpSenderMail')
            smtpUser = request.data.get('smtpUser')
            smtpPassword = request.data.get('smtpPassword')

            allRecord = smtpSet.objects.all()
            for record in allRecord:
                record.delete()

            smtpSet.objects.create(SMTPServer=smtpServerName, SMTPPort=smtpServerPort, sendMail=smtpSenderMail, SMTPUser=smtpUser, SMTPPasswd=smtpPassword)

            ret = get_error_result("Success")
            return JSONResponse(ret)

        except Exception as e:

            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("SetSmtpServerInfoError")
            return JSONResponse(resp)



class addMail(APIView):

    def post(self, request, *args, **kwargs):

        newMail = request.data.get('mail')
        print(newMail)


        try:
            mails.objects.create(mail=newMail)

            ret = get_error_result("Success")
            return JSONResponse(ret)
           
        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("AddMailError")
            return JSONResponse(resp)


def makeMail(fromAddr, toAddr, mailTitle, content):
    mail = MIMEMultipart()
    mail['From'] = fromAddr   # 构造邮件头From
    mail['To'] = Header(toAddr, 'utf-8')            # 构造邮件头To
    mail['Subject'] = Header(mailTitle, 'utf-8')      # 构造邮件主题

    mail.attach(MIMEText(content, 'plain', 'utf-8'))
    return mail



class deleteMailRecord(APIView):

    def post(self, request, *args, **kwargs):

        mail = request.data.get('mail')

        try:

            delMail = mails.objects.filter(mail__exact=mail)
            delMail.delete()

            ret = get_error_result("Success")
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("DeleteMailDataTableError")
            return JSONResponse(resp)
        
#等级列表：1 :提示     2：警告     3：严重
#硬raid     3    
#软raid     3
#性能监控   3
#双控       3
#服务监控   3
#日志监控   1
class eventClassificationStatistics(APIView):

    def post(self, request, *args, **kwargs):

        try:

            recordList = []
                
            recordList = warnRecord.objects.exclude(hadNotified__gt=0).all()

            tipCount = 0
            tipList = []

            warnCount = 0
            warnList = []

            dangerCount = 0
            dangerList = []

            for index in range(len(recordList)):
                obj = {}
                obj['uuid'] = recordList[index].uuid#text
                obj['level'] = recordList[index].level#int
                obj['time'] = recordList[index].time#datetime
                obj['desc'] = recordList[index].desc#text
                obj['hadNotified'] = recordList[index].hadNotified#int

                if obj['level']  == 1:
                    tipCount = tipCount + 1
                    tipList.append(obj)
                elif obj['level']  == 2:
                    warnCount = warnCount + 1
                    warnList.append(obj)
                elif obj['level']  == 3:
                    dangerCount = dangerCount + 1
                    dangerList.append(obj)
                else:
                    pass

            tipObj = {'eventLevel': 1, 'count': tipCount, 'theList':tipList}
            warnObj = {'eventLevel': 2,'count': warnCount, 'theList':warnList}
            dangerObj = {'eventLevel': 3,'count': dangerCount, 'theList':dangerList}

            warnInfoObjList = []
            warnInfoObjList.append(tipObj)
            warnInfoObjList.append(warnObj)
            warnInfoObjList.append(dangerObj)

            ret = get_error_result("Success", warnInfoObjList)
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetWarnInfoError")
            return JSONResponse(resp)


class hadViewed(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'uuid': openapi.Schema(type=openapi.TYPE_STRING, description='uuid'),
        },
        required=['uuid']
    ))    


    def post(self, request, *args, **kwargs):

        uuidList = []
        uuid = request.data.get('uuid')
        uuidList.append(uuid)

        try:

            modifyNotifyColumn(uuidList, 2)

            ret = get_error_result("Success")
            return JSONResponse(ret)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("ModifyHadViewError")
            return JSONResponse(resp)


class deleteWarnTableRecord(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'uuidList': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='uuid'),
        },
        required=['uuidList']
    ))    

    def post(self, request, *args, **kwargs):

        uuidList = []
        uuidList = request.data.get('uuidList')

        try:
            for theUuid in  uuidList:
                print(theUuid)
                recordObj = warnRecord.objects.filter(uuid=theUuid)
                recordObj.delete()
                
            ret = get_error_result("Success")
            return JSONResponse(ret)

        except Exception as e:

            logger.error(''.join(traceback.format_exc()))
            logger.debug('删除告警表信息失败！！！')
            resp = get_error_result("DeleteWarmTableRecordError")
            return JSONResponse(resp)



def circleDealWarnthread():

    uuidList = []

    while True:
        time.sleep(30)
        try:

            print('circle Deal Warn...')

            level = '0'
            leveSetTime = datetime.datetime.strptime('1990-1-1 00:00:00', "%Y-%m-%d %H:%M:%S")
            recordList = []
                
            result = selectWarnDateTableAndLevelConfig()
            status = result[0]
            level = result[1]
            leveSetTime = result[2]
            recordList = result[3]
            if(status == False):
                logger.debug('查询告警数据库和告警级别配置文件失败')
                continue

            result = selectMailDateTableAndSmtpServerConfig()
            status = result[0]
            smtpServerAddr = result[1]
            smtpServerPort = result[2]
            smtpSendMail = result[3]
            smtpUser = result[4]
            smtpPasswd = result[5]
            mailList = result[6]
            if(status == False or len(smtpServerAddr) == 0 or len(smtpServerPort) == 0 or len(smtpSendMail) == 0 or len(smtpUser) == 0 or len(smtpPasswd) == 0):
                logger.debug('查询告警邮箱数据库和smtp配置文件失败')
                continue

            smtp = smtplib.SMTP_SSL(smtpServerAddr, smtpServerPort)        # 此处直接一步到位
            smtp.login(smtpUser, smtpPasswd)  

            uuidList = []
            setLevelTimeValue = leveSetTime.timestamp()
            for index in range(len(recordList)):
                obj = {}
                obj['uuid'] = recordList[index][0]#text
                obj['level'] = recordList[index][1]#int
                obj['time'] = recordList[index][2]#datetime
                obj['desc'] = recordList[index][3]#text
                obj['hadNotified'] = recordList[index][4]#int

                value = obj['time'].timestamp()

                if(value >= setLevelTimeValue and obj['level'] >= int(level) and obj['hadNotified'] != 1):
                    print(obj)
                    for mail in mailList:
                        time.sleep(15)
                        smtp.sendmail(smtpSendMail, mail[0], makeMail(smtpSendMail, mail[0], '双击存储通知信息', obj['time'].strftime('%Y-%m-%d %H:%M:%S.%f') + ': ' + obj['desc']).as_string())
                        uuidList.append(obj['uuid'])
                    

            smtp.quit()
        
        except Exception as e:

            logger.error(''.join(traceback.format_exc()))

        print(uuidList)
        modifyNotifyColumn(uuidList, 1)



class testMail(APIView):

    def post(self, request, *args, **kwargs):

        result = selectMailDateTableAndSmtpServerConfig()
        status = result[0]
        smtpServerAddr = result[1]
        smtpServerPort = result[2]
        smtpSendMail = result[3]
        smtpUser = result[4]
        smtpPasswd = result[5]
        mailList = result[6]
        if(status == False or len(smtpServerAddr) == 0 or len(smtpServerPort) == 0 or len(smtpSendMail) == 0 or len(smtpUser) == 0 or len(smtpPasswd) == 0):
            logger.debug('查询告警邮箱数据库和smtp配置文件失败')
            ret = get_error_result("TestMailError")
            return JSONResponse(ret)
        

        smtp = smtplib.SMTP_SSL(smtpServerAddr, smtpServerPort)        # 此处直接一步到位
        smtp.login(smtpUser, smtpPasswd)
        for mail in mailList:
            smtp.sendmail(smtpSendMail, mail[0], makeMail(smtpSendMail, mail[0], '双击存储邮箱测试信息', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f') + ': ' + "邮箱测试ok").as_string())

        smtp.quit()
        ret = get_error_result("Success")
        return JSONResponse(ret)



thread = threading.Thread(target=circleDealWarnthread)
thread.start()


from web_manage.hardware.hardRaid.views import getAllPhysicalDiskList
from web_manage.perfdata.models import *
from web_manage.cluster.models import *
from web_manage.hardware.hardRaid.models import *
from storesys.timerTasks import DblCtlSysRunStatus
from web_manage.hardware.hardRaid.views import getEvent
import ctypes

#等级列表：1 :提示     2：警告     3：严重
#硬raid     3    
#软raid     3
#性能监控   3
#双控       3
#服务监控   3
#日志监控   1

HARD_RAID_LEVEL = 3
SOFT_RAID_LEVEL = 3
PERFORMANCE_MONITOR_LEVEL = 3
DOUBLE_CONTROL_LEVEL = 3
SERVER_MONITOR_LEVEL = 3
LOG_MONITOR_LEVEL = 1

#------------------------usage-------------------------
CPU_USAGE = 90.0
MEMORY_USAGE = 90.0
DISK_USAGE = 90.0
NETWORK_USAGE = 90.0

def hardDiskMonitor():

    hardRaidPosition = 0
    cpuQueryPosition = 0
    memoryQueryPosition = 0
    diskQueryPosition = 0
    networkQueryPosition = 0

    warnQueryPosList = warnQueryPositionRecord.objects.all()
    for ele in warnQueryPosList:
        if ele.tableName == 'cpu_monitoring_data':
            cpuQueryPosition = int(ele.position)
        elif ele.tableName == 'mem_monitoring_data':
            memoryQueryPosition = int(ele.position)
        elif ele.tableName == 'diskio_monitoring_data':
            diskQueryPosition = int(ele.position)
        elif ele.tableName == 'network_monitoring_data':
            networkQueryPosition = int(ele.position)
        elif ele.tableName == 'hardRaidError':
            hardRaidPosition = int(ele.position)
        else:
            pass

    hardRaidNewPosition = hardRaidPosition
    cpuQueryNewPosition = cpuQueryPosition
    memoryQueryNewPosition = memoryQueryPosition
    diskQueryNewPosition = diskQueryPosition
    networkQueryNewPosition = networkQueryPosition

##########################硬raid##########################
    physicalDiskInfoList = hardRaidError.objects.all()
    for ele in physicalDiskInfoList:
        if ele.id > hardRaidPosition:
            string = ele.desc
            insertNewRecord(HARD_RAID_LEVEL, string)
        hardRaidNewPosition = ele.id

    theStr = getEvent()
    if len(theStr) > 0:
        insertNewRecord(HARD_RAID_LEVEL, theStr)

##########################软raid##########################


###########################性能监控#########################
    cpuAllRecordList = CpuMonitoringData.objects.all()
    for ele in cpuAllRecordList:
        if ele.id > cpuQueryPosition and float(ele.usage) > CPU_USAGE:
            string = f'注意cpu使用率超过{CPU_USAGE}'
            insertNewRecord(PERFORMANCE_MONITOR_LEVEL, string)
        cpuQueryNewPosition = ele.id
    
    memoryAllRecordList = MemMonitoringData.objects.all()
    for ele in memoryAllRecordList:
        if ele.id > memoryQueryPosition and float(ele.mem_percent) > MEMORY_USAGE:
            string = f'注意内存使用率超过{MEMORY_USAGE}'
            insertNewRecord(PERFORMANCE_MONITOR_LEVEL, string)
        memoryQueryNewPosition = ele.id

    diskAllRecordList = DiskioMonitoringData.objects.all()
    for ele in diskAllRecordList:
        if ele.id > diskQueryPosition and (float(ele.read_count) > DISK_USAGE or float(ele.write_speed) > DISK_USAGE):
            string = f'注意磁盘的读/写速率超过{DISK_USAGE}'
            insertNewRecord(PERFORMANCE_MONITOR_LEVEL, string)
        diskQueryNewPosition = ele.id

    networkAllRecordList = NetworkMonitoringData.objects.all()
    for ele in networkAllRecordList:
        if ele.id > networkQueryPosition and (float(ele.recv_speed) > NETWORK_USAGE or float(ele.sent_speed) > NETWORK_USAGE):
            string = f'注意网络的收/发速率超过{NETWORK_USAGE}'
            insertNewRecord(PERFORMANCE_MONITOR_LEVEL, string)
        networkQueryNewPosition = ele.id


###########################双控#########################
    clusterAllRecordList = ClusterNode.objects.all()#最多只有一条记录
    if len(clusterAllRecordList) > 0:
        if clusterAllRecordList[0].double_control_status != DblCtlSysRunStatus.SingleNode.value and \
           clusterAllRecordList[0].double_control_status != DblCtlSysRunStatus.NormalDoubleControl.value:
            string = f'双控服务异常：{clusterAllRecordList[0].double_control_status}'
            insertNewRecord(DOUBLE_CONTROL_LEVEL, string) 

###########################日志监控#########################


###########################服务监控#########################
    serverNameList = ['storemng', 'smb', 'nfs', 'vsftpd', 'tgtd', 'iscsid']
    for server in serverNameList:
        status, result = run_cmd('systemctl status ' + server + ' |grep "Active" |awk \'{print $2}\'')
        if result.split('\n')[0] == 'inactive':
           string = f'服务<{server}>未启动'
           insertNewRecord(SERVER_MONITOR_LEVEL, string)  
        elif result.split('\n')[0] != 'active':
            string = f'服务<{server}>不存在'
            insertNewRecord(SERVER_MONITOR_LEVEL, string)  

###########################################################
    if len(warnQueryPosList) > 0:#不是空表，说明已经不是第一次，只需要更新即可
        for ele in warnQueryPosList:
            if ele.tableName == 'cpu_monitoring_data':
                ele.position = str(cpuQueryNewPosition)
                ele.save()
            elif ele.tableName == 'mem_monitoring_data':
                ele.position = str(memoryQueryNewPosition)
                ele.save()
            elif ele.tableName == 'diskio_monitoring_data':
                ele.position = str(diskQueryNewPosition)
                ele.save()
            elif ele.tableName == 'network_monitoring_data':
                ele.position = str(networkQueryNewPosition)
                ele.save()
            elif ele.tableName == 'hardRaidError':
                ele.position = str(hardRaidNewPosition)
                ele.save()
            else:
                pass
    else:
        warnQueryPositionRecord.objects.create(tableName='hardRaidError', position=hardRaidNewPosition)
        warnQueryPositionRecord.objects.create(tableName='cpu_monitoring_data', position=cpuQueryNewPosition)
        warnQueryPositionRecord.objects.create(tableName='mem_monitoring_data', position=memoryQueryNewPosition)
        warnQueryPositionRecord.objects.create(tableName='diskio_monitoring_data', position=diskQueryNewPosition)
        warnQueryPositionRecord.objects.create(tableName='network_monitoring_data', position=networkQueryNewPosition)




def circleMonitorSystemthread():

    while(True):

        try:
            print('monitor system ...')

            hardDiskMonitor()
        
            time.sleep(30)

        except Exception as e:

            logger.error(''.join(traceback.format_exc()))

        

        
thread2 = threading.Thread(target=circleMonitorSystemthread)
thread2.start()



