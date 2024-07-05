#2023-12-28 :更新了raid获取空闲分区函数，过滤掉iscsi虚拟盘

import os
import time
import traceback
import logging
from django.http import Http404, HttpResponseServerError
from rest_framework.views import APIView
from web_manage.common.utils import JSONResponse, WebPagination, get_error_result
from web_manage.admin.models import OperationLog
from web_manage.admin.serializers import OperationLogSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from web_manage.common.cmdutils import run_cmd

logger = logging.getLogger(__name__)

word = 'spare-group=group1'

RAID_CONFIG_FILE = '/etc/mdadm.conf'

MAIL_PATH = '/etc/raid_emails'
MAIL_CONFIG_PATH = '/etc/raid_emails_config'


def restartDevMonitor():

    # ----------raid name----------------
    result = os.popen('mdadm -Dsvv |grep \'/dev/md/.*:\' |awk -F\':\' \'{print $1}\'', "r")
    names = result.readlines()
    result.close()
    index = 0
    for ele in names:
        names[index] = ele.split('\n')[0]#去掉每个字符串末尾的换行符
        index += 1
    
    logger.debug(names)#name is list[]

    raidString = ''
    for ele in names:
        raidString = raidString + ' ' + ele

    cmd = 'ps -ef |grep "mdadm --monitor" |grep -v "grep"'  

    result = os.popen(cmd, 'r')
    pidLineList = result.readlines()
    result.close()
    if len(pidLineList) > 0:
        for line in pidLineList:
            if line.find('--mail') == -1:#not mail deamon
                logger.debug('the monitor line:' + line.split('\n')[0])
                pid = line.split('\n')[0].split()[1]
                os.system('kill -9 ' + pid)

    os.system('mdadm --monitor' + raidString + ' &')


def getFilelines(fileName):
    try:
        file = open(fileName, "r")
        lines = file.readlines()
        file.close()
        return lines
    except FileNotFoundError:
        logger.debug('no this file ' + fileName)
        return []
    except PermissionError:
        logger.debug('no permission opne' + fileName)
        return []

def getAlineInFile(fileName, match, offset):
    try:
        file = open(fileName, "r")
        lines = file.readlines()
        #print(fileName, 'content : ', lines)

        for index in range(len(lines)):
            if lines[index].find(match) >= 0:
                file.close()
                return lines[index + offset]
        
        file.close()
        return ''
    except FileNotFoundError:
        logger.debug('no this file ' + fileName)
        return ''
    except PermissionError:
        logger.debug('no permission opne' + fileName)
        return ''

#word is string type
def appendAWordInTheEndOfALine(fileName, match, word):

    theLineIndex = -1
    try:
        file = open(fileName, "r")
        lines = file.readlines()
        #print(fileName, 'content : ', lines)

        for index in range(len(lines)):
            if lines[index].find(match) >= 0:
                theLineIndex = index
                break
        
        file.close()

        if theLineIndex == -1:
            logger.debug('occur a error, no find the raid in the ' + fileName)
            return
        
        lines[theLineIndex] = lines[theLineIndex].split('\n')[0] + ' ' + word + '\n'
        file = open(fileName, "w")
        file.writelines(lines)
        file.close()
        return
    
    except FileNotFoundError:
        logger.debug('no this file:' + fileName)
        return
    except PermissionError:
        logger.debug('no permission opne' + fileName)
        return


#lines[0] = 'abc'
#lines[1] = 'efg'
#lines[2] = 'hij' . . .  (match)
#lines[3] = 'klm'                 (+rang = 3)
#lines[4] = 'opq' . . .   
#删除从匹配行到rang范围的行，rang的正负决定删除的方向
def delLinesInFile(fileName, match, rang):

    if rang == 0:
        logger.debug('参数有误')
        return -1

    file = open(fileName, "r")
    lines = file.readlines()
    logger.debug(f'{fileName}, content :  {lines}')

    for index in range(len(lines)):
        
        if lines[index].find(match) >= 0:

            if rang > 0:

                for cnt in range(rang):#[0 , rang)
                    del lines[index]

            else:

                for cnt in range( abs(rang) ):#[0 , rang)
                    del lines[index + rang + 1]

            break
    
    file.close()
    # print(lines)

    file = open(fileName, "w")

    file.writelines(lines)

    file.close()


def getFreeZoneFun():

    tmpFile = "/tmp/freeZoneList.tmp"

    os.system("lsblk -o NAME,SIZE,TYPE -n -p > " + tmpFile)

    file = open(tmpFile, "r")
    lines = file.readlines()
    file.close()
    
    eleCount = len(lines)
    freeZoneList = []
    for index in range(eleCount):

        if (((index + 1) < eleCount) and (lines[index + 1].find('├─') >=0 or lines[index + 1].find('└─') >=0) or\
            (lines[index].find('├─') >=0 or lines[index].find('└─') >=0)):
            
            continue

        else:

            freeZoneList.append(lines[index])

    logger.debug('all dev:')
    logger.debug(freeZoneList)
    freeZoneObjList = []
    for index in range(len(freeZoneList)):

        str = freeZoneList[index].split('\n')[0]#去掉末尾的\n
        infoList = str.split()#去掉中间的空字符串
        
        obj = {}
        obj['name'] = infoList[0]
        obj['size'] = infoList[1]
        obj['type'] = infoList[2]

        freeZoneObjList.append(obj)

    #--------------------过滤掉物理卷-------------------
    vglines = []
    usefulVgList = []
    result = os.popen("pvs |awk 'NR!=1{print $1}'", "r")
    vglines = result.readlines()
    result.close()

    
    logger.debug("pv dev:")
    logger.debug(vglines)
    for index in range(len(vglines)):
        if vglines[index].find("WARNING") == -1:
            usefulVgList.append(vglines[index].split('\n')[0])

    logger.debug("remove WARNING pv dev:")
    logger.debug(usefulVgList)

    outIndex = 0
    while True:
        if outIndex < len(freeZoneObjList):
            for inIndex in range(len(usefulVgList)):
                if freeZoneObjList[outIndex]['name'] == usefulVgList[inIndex]:
                    del  freeZoneObjList[outIndex]
                    outIndex = outIndex - 1
                    break
            
            outIndex = outIndex + 1
        else:
            break

    # #-------------------过滤掉iscsi虚拟盘------------------------
    # iscsiDevLines = []
    # result = os.popen("lsblk -pS -o NAME,TRAN |grep 'iscsi' |awk '{print $1}'", "r")
    # iscsiDevLines = result.readlines()
    # result.close()
    # logger.debug("iscsi dev:")
    # logger.debug(iscsiDevLines)
    # for index in range(len(iscsiDevLines)):
    #     iscsiDevLines[index] = iscsiDevLines[index].split('\n')[0]

    # outIndex = 0
    # while True:
    #     if outIndex < len(freeZoneObjList):
    #         for inIndex in range(len(iscsiDevLines)):
    #             if freeZoneObjList[outIndex]['name'] == iscsiDevLines[inIndex]:
    #                 del  freeZoneObjList[outIndex]
    #                 outIndex = outIndex - 1
    #                 break
            
    #         outIndex = outIndex + 1
    #     else:
    #         break

    logger.debug('finally free dev:')
    logger.debug(freeZoneObjList)

    return freeZoneObjList



def getFreeRaidFun():

    tmpFile = "/tmp/freeRaidList.tmp"

    res = os.system("lsblk -o NAME,SIZE,TYPE -n /dev/md/* > " + tmpFile)
    if res != 0:
        return []

    file = open(tmpFile, "r")
    lines = file.readlines()
    file.close()
    
    eleCount = len(lines)
    freeRaidList = []
    for index in range(eleCount):

        if (((index + 1) < eleCount) and (lines[index + 1].find('├─') >=0 or lines[index + 1].find('└─') >=0) or\
            (lines[index].find('├─') >=0 or lines[index].find('└─') >=0)):
            
            continue

        else:

            freeRaidList.append(lines[index])

    logger.debug('all raid:')
    logger.debug(freeRaidList)

    raidLinkMapObj = []
    result = os.popen('ls -lrt /dev/md/* |awk \'{print $9"   "$11}\'', 'r')
    raidLinkList = result.readlines()
    result.close()
    for ele in raidLinkList:
        obj = {}
        obj['linkName'] = ele.split('\n')[0].split()[0]
        obj['raidName'] = ele.split('\n')[0].split()[1]
        logger.debug('linkName:' + obj['linkName'] + "  raidName:" + obj['raidName'])
        raidLinkMapObj.append(obj)

    freeRaidObjList = []
    for index in range(len(freeRaidList)):

        str = freeRaidList[index].split('\n')[0]#去掉末尾的\n
        infoList = str.split()#去掉中间的空字符串

        if(infoList[2] != 'raid5' and infoList[2] != 'raid6'):
            continue
        
        for ele in raidLinkMapObj:
            
            if(ele['raidName'].find(infoList[0]) != -1):
                
                obj = {}
                obj['name'] = ele['linkName']
                obj['size'] = infoList[1]
                obj['type'] = infoList[2]
                freeRaidObjList.append(obj)


    logger.debug('finally free raid dev:')
    logger.debug(freeRaidObjList)

    return freeRaidObjList




def getMails():

    try:
        file = open(MAIL_PATH, "r")
    
        lines = file.readlines()
        file.close()

        mailList = []

        for ele in lines:

            mailList.append(ele.split('\n')[0]) #去掉末尾的‘\n’

        return mailList
    except FileNotFoundError:
        logger.debug('no this file:' + MAIL_PATH)
        return []
    except PermissionError:
        logger.debug('no permission opne' + MAIL_PATH)
        return []

def getMailsConfig():

    try:
        file = open(MAIL_CONFIG_PATH, "r")
        lines = file.readlines()
        file.close()

        configLines = []

        for ele in lines:

            configLines.append(ele.split('\n')[0].split()) #去掉末尾的‘\n’和中间的空格 [['/dev/md/md1', true], ...]

        configTableData = []

        for ele in configLines:

            if ele[1] == 'true':
                configTableData.append({'status': True, 'raidName': ele[0]})

            else:
                configTableData.append({'status': False, 'raidName': ele[0]})

        return configTableData
    
    except FileNotFoundError:
        logger.debug('no this file:' + MAIL_CONFIG_PATH)
        return []
    except PermissionError:
        logger.debug('no permission opne' + MAIL_CONFIG_PATH)
        return []


def writeMails(mails):

    file = open(MAIL_PATH, "w")

    for ele in mails:
    
        file.writelines(ele + '\n')

    file.close()


def writeailsConfig(mailsConfig):

    file = open(MAIL_CONFIG_PATH, "w")

    maliConfigLines = []

    for ele in mailsConfig:

        if ele['status'] == True:
            maliConfigLines.append(ele['raidName'] + '  ' + 'true' + '\n')
        
        else:
            maliConfigLines.append(ele['raidName'] + '  ' + 'false' + '\n')
    
    file.writelines(maliConfigLines)

    file.close()


def startOneRaidMonitor(raidName):

    mailList = getMails()

    for mail in mailList:

        cmd = 'mdadm --monitor ' + raidName + ' --mail ' + mail + '&'
        logger.debug('start monitor thread cmd:', cmd)
        os.system(cmd)


def stopOneRaidMonitor(raidName):

    cmd = 'ps -ef | grep "mdadm --monitor ' + raidName + '" |awk \'{print $2}\''
    logger.debug('find monitor thread cmd:', cmd)
    result = os.popen(cmd, "r")
    monitorList = result.readlines()
    result.close()
    monitorList.pop()#去掉最后一行无用信息

    for ele in monitorList:

        pid = ele.split('\n')[0]
        cmd = 'kill ' + pid
        os.system(cmd)


class GetRaidInfoListView(APIView):

    @swagger_auto_schema(None)
 
    def post(self, request, *args, **kwargs):

        restartDevMonitor()

        try:
            logger.debug("get raid info post request")
            
            # ----------raid name----------------
            result = os.popen('mdadm -Dsvv |grep \'/dev/md/.*:\' |awk -F\':\' \'{print $1}\'', "r")
            names = result.readlines()
            result.close()
            index = 0
            for ele in names:
                names[index] = ele.split('\n')[0]#去掉每个字符串末尾的换行符
                index += 1
            
            logger.debug("the raid names:")
            logger.debug(names)#name is list[]

            # ----------raid status----------------
            status = []
            for name in names:
                result = os.popen('mdadm -D ' + name + '|grep \'State :\' |awk -F\':\' \'{print $2}\'', "r")
                status.append(result.readline())
                result.close()

            index = 0
            for ele in status:
                status[index] = ele.split('\n')[0].strip()#去掉每个字符串末尾的换行符，再去掉前面的空格
                index += 1
            
            logger.debug(status)

            # ----------raid levels----------------
            levels = []
            for name in names:
                result = os.popen('mdadm -D ' + name + '|grep \'Raid Level :\' |awk -F\':\' \'{print $2}\'', "r")
                levels.append(result.readline())
                result.close()

            index = 0
            for ele in levels:
                levels[index] = ele.split('\n')[0].strip()#去掉每个字符串末尾的换行符，再去掉前面的空格
                index += 1
            
            logger.debug(levels)

            # ----------raid totalSize----------------
            totalSize = []
            for name in names:
                result = os.popen('mdadm -D ' + name + '|grep \'Array Size :\' |awk -F\' \' \'{print $7 $8}\'', "r")
                totalSize.append(result.readline())
                result.close()

            index = 0
            for ele in totalSize:
                totalSize[index] = ele.split(')\n')[0]#去掉每个字符串末尾的 ) 和 换行符
                index += 1
            
            logger.debug(totalSize)

            # ----------raid usedSize----------------
            usedSize = []
            for name in names:
                result = os.popen('mdadm -D ' + name + '|grep \'Used Dev Size :\' |awk -F\' \' \'{print $8 $9}\'', "r")
                usedSize.append(result.readline())
                result.close()

            index = 0
            for ele in usedSize:
                usedSize[index] = ele.split(')\n')[0]#去掉每个字符串末尾的 ) 和 换行符
                if usedSize[index] == '':
                    usedSize[index] = '0'
                index += 1
            
            logger.debug(usedSize)

            # ----------raid childDves----------------
            childDves = []
            for name in names:
                line =  getAlineInFile(RAID_CONFIG_FILE, name, 1)
                if line == '':#没有找到该阵列在配置文件中的记录,bug异常
                    logger.error('mdadm.conf not this md device:' + name + ' record')
                    ret = get_error_result("GetRaidInfoListError")
                    return JSONResponse(ret)
                else:
                    line.split('\n')[0].strip()#去掉每个字符串末尾的换行符,再去掉前边的空格
                    childDves.append(line.split('=')[1])#去掉前缀‘devices=’

            logger.debug(childDves)

            globalSpare = []
            for name in names:
                line =  getAlineInFile(RAID_CONFIG_FILE, name, 0)
                if line.find(word) >= 0:
                    globalSpare.append(True)
                else:
                    globalSpare.append(False)

            logger.debug(globalSpare)

            res = []
            for i in range(len(names)):
                ret = dict()
                ret['name'] = names[i]
                ret['status'] = status[i]
                ret['level'] = levels[i]
                ret['totalSize'] = totalSize[i]
                ret['usedSize'] = usedSize[i]
                ret['sonDevices'] = childDves[i]
                ret['inGlobalSpare'] = globalSpare[i]
                res.append(ret)

            logger.debug('get raid info sucess!!!')
            return JSONResponse(res)
        
        except Exception as err:
            logger.error("get raid info list error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetRaidInfoListError")
            return JSONResponse(ret)


OUTPUT_LOG_FILE='logFile'

#获取物理逻辑卷使用的raid
def PvsDev():
    allLines = []
    result= os.popen('pvs |awk \'{print $1}\'', "r")
    allLines = result.readlines()
    result.close()

    for index in range(len(allLines)):
        allLines[index] = allLines[index].split('\n')[0]

    logger.debug(f'所有物理卷:{allLines}')
    return allLines

def getRaidAndDevMap():
    allLines = []
    result = os.popen('mdadm -Dsv |grep "ARRAY" |awk \'{print $2}\'', "r")#获取所有的/dev/md/xxx raid设备
    allLines = result.readlines()
    result.close()

    for index in range(len(allLines)):
        allLines[index] = allLines[index].split('\n')[0]

    map = []
    for ele in allLines:#找到/dev/md/xxx 对应的连接设备/dev/1xx
        result = os.popen('ls -lrt ' + ele + ' |awk \'{print $NF}\' |awk -F"/" \'{print $2}\'')
        lines = result.readlines()
        result.close()
        if len(lines) > 0:
            dev = lines[0].split('\n')[0]
            ralation = {}
            ralation['raid'] = ele
            ralation['dev'] = dev
            map.append(ralation)

        else:
            logger.debug('getRaidAndDevMap 函数中获取 ' + ele +'对应的/dev/xxx设备失败！！！' )

    logger.debug(f'mdadm raid对应的/dev设备映射表：{map}')
    return map


def theMaddmRaidUseToPysicalVolume(mdadmRaid):

    dev = ''
    status = True

    pysicalVolumeDev = PvsDev()

    MaddmRaidToDevMap = getRaidAndDevMap()

    try:
        for ele in MaddmRaidToDevMap:
            if ele['raid'] == mdadmRaid:
                dev =  ele['dev']
                logger.debug(mdadmRaid + '对应的dev设备是:' + dev)
                break

        if len(dev) > 0:
            for ele in pysicalVolumeDev:
                if ele.find(dev) != -1:
                    return status
            
        return False

    except Exception as err:

        status = False
        return status


def runCmdAndGetLog(cmdString):
    status, result = run_cmd(cmdString)
    return status, result


class rmRaids(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raid': openapi.Schema(type=openapi.TYPE_STRING, description='将要删除raid的名字'),
            'chilDevs': openapi.Schema(type=openapi.TYPE_STRING, description='该阵列的所有子设备列表，比如:"/dev/sda,/dev/sdb,/dev/sdc"')
        },
        required=['raid', 'chilDevs'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug("remove raid post request")

            # print("remove raids : ", request.data)

            childs = []

            for ele in request.data:

                if theMaddmRaidUseToPysicalVolume(ele['raid']) == True:
                    logger.debug(ele['raid'] + '被用来创建物理卷了')
                    ret = get_error_result("RaidHadBeUsed")
                    return JSONResponse(ret)
                
                status, res = runCmdAndGetLog('mdadm -S ' + ele['raid'])
                if status != 0:
                    ret = get_error_result("ReMoveRaidError")
                    return JSONResponse(ret)

                if ele['chilDevs'].find('/dev/md/') == -1:
                    childs = ele['chilDevs'].replace(',' , ' ')#把ele['chilDevs']字符串中的，用空格替代
                    #os.system('mdadm --misc --force --zero-superblock ' + childs)
                    status, res = runCmdAndGetLog('mdadm --misc --force --zero-superblock ' + childs)
                    if status != 0:
                        ret = get_error_result("ReMoveRaidError")
                        return JSONResponse(ret)

                delLinesInFile(RAID_CONFIG_FILE, ele['raid'], 2)

              #  stopOneRaidMonitor(ele['raid'])

              #  delLinesInFile(MAIL_CONFIG_PATH, ele['raid'], 1)

            restartDevMonitor()

            ret = {'code':0, 'msg': '删除raid成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("get raid info list error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("ReMoveRaidError")
            return JSONResponse(ret)
        


class createRaid(APIView):
    
    raidLevels = {
        'raid0' : '0',
        'raid1' : '1',
        'raid5' : '5',
        'raid6' : '6',
        'raid10' : '10',
        'raid50' : '0',
        'raid60' : '0',
    }

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'name': openapi.Schema(type=openapi.TYPE_STRING, description='将要创建raid的名字'),
            'level': openapi.Schema(type=openapi.TYPE_STRING, description='raid的级别'),
            'childDevNumber': openapi.Schema(type=openapi.TYPE_NUMBER, description='raid子设备的数量'),
            'childDevList': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid子设备列表'),
            'createMode': openapi.Schema(type=openapi.TYPE_STRING, description='raid创建模式,"nomal"/"quickly"'),
        },
        required=['name', 'level', 'childDevNumber', 'childDevList', 'createMode'],
    ))

    def post(self, request, *args, **kwargs):

        ret = {}
        
        try:
            logger.debug("create raid post request")
            logger.debug(request.data)

            cmd = 'mdadm -Cv  ' + request.data['name'] + \
                      '  -l  ' + self.raidLevels[request.data['level']] +\
                      '  -n  ' + str(request.data['childDevNumber'])
            
            for dev in request.data['childDevList']:

               cmd = cmd + ' ' + dev

            cmd += '  --run'

            if request.data['createMode'] != 'normal':

                cmd += '  --assume-clean'

            logger.debug(cmd)

            #os.system(cmd)
            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("CreateRaidError")
                return JSONResponse(ret)

            os.system('mdadm -Dsv  ' + request.data['name'] + '  >> ' + RAID_CONFIG_FILE)

            #os.system('echo \'' + request.data['name'] + '  ' + 'false\'  >> ' + MAIL_CONFIG_PATH)

            restartDevMonitor()

            ret['code'] = 0
            ret['msg'] = '创建raid成功'
            return JSONResponse(ret)

        except Exception as err:
            logger.error("create raid error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("CreateRaidError")
            return JSONResponse(ret)
    


class setGlobalSpare(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raid': openapi.Schema(type=openapi.TYPE_STRING, description='将要加入热备组raid的名字'),
            'action': openapi.Schema(type=openapi.TYPE_STRING, description='操作<join/out>'),
        },
        required=['raid', 'action'],
    ))

    def post(self, request, *args, **kwargs):

        msg = ''

        ret = {}

        try:
            logger.debug("set global spare post request")

            # print("remove raids : ", request.data)

            if theMaddmRaidUseToPysicalVolume(request.data['raid']) == True:
                logger.debug(request.data['raid'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            if(request.data['action'] == 'join'):
                line = getAlineInFile(RAID_CONFIG_FILE, request.data['raid'], 0)
                if len(line) <= 0:
                    logger.debug('没有在配置文件中找到该raid的记录')
                    msg = '没有在配置文件中找到该raid的记录'

                elif line.find(word) != -1:#find
                    logger.debug('该raid已经在热备组中，无需重复操作')
                    msg = '该raid已经在热备组中，无需重复操作'

                else:
                    appendAWordInTheEndOfALine(RAID_CONFIG_FILE, request.data['raid'], word)
                    restartDevMonitor()
                    time.sleep(1.5)

                    fileLineList = getFilelines(RAID_CONFIG_FILE)
                    os.system('mdadm -Dsv  > ' + RAID_CONFIG_FILE)#覆盖
                    time.sleep(1)
                    for line in fileLineList:
                        if line.find(word) >= 0:
                            appendAWordInTheEndOfALine(RAID_CONFIG_FILE, line.split()[1], word)
                    msg = '加入热备组成功'
            else:
                line = getAlineInFile(RAID_CONFIG_FILE, request.data['raid'], 0)
                if len(line) <= 0:
                    logger.debug('没有在配置文件中找到该raid的记录')
                    msg = '没有在配置文件中找到该raid的记录'

                elif line.find(word) == -1:#not find
                    logger.debug('该raid不在热备组中，无需重复操作')
                    msg = '该raid不在热备组中，无需重复操作'

                else:
                    delLinesInFile(RAID_CONFIG_FILE, request.data['raid'], 2)#delete the old record
                    os.system('mdadm -Dsv  ' + request.data['raid'] + '  >> ' + RAID_CONFIG_FILE)
                    msg = '退出热备组成功'
                    restartDevMonitor()

            
            ret['code'] = 0
            ret['msg'] = msg
            return JSONResponse(ret)

        except Exception as err:
            logger.error("get raid info list error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("JoinGlobalSpareError")
            return JSONResponse(ret)
        


class getFreeZone(APIView):
    
    def post(self, request, *args, **kwargs):

        restartDevMonitor()

        try:
            logger.debug("get free zone list post request")

            freeZoneObjList = getFreeZoneFun()

            logger.debug(freeZoneObjList)
            return JSONResponse(freeZoneObjList)

        except Exception as err:
            logger.error("get free zone list error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetFreeZoneError")
            return JSONResponse(ret)


class getFreeRaid(APIView):
    
    def post(self, request, *args, **kwargs):

        restartDevMonitor()

        try:
            logger.debug("get free raid list post request")

            freeRiadObjList = getFreeRaidFun()

            logger.debug(freeRiadObjList)
            return JSONResponse(freeRiadObjList)

        except Exception as err:
            logger.error("get free raid list error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetFreeRaidError")
            return JSONResponse(ret)



class getRaidDetail(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'theRaidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
        },
        required=['theRaidName'],
    ))


    def post(self, request, *args, **kwargs):

        restartDevMonitor()

        try:
            logger.debug("get raid: " + request.data['theRaidName'] + " detail post request")

            obj = {}
            result = os.popen('mdadm -D ' + request.data['theRaidName'], "r")
            obj['detailString'] = result.readlines()# is list
            result.close()

            result = os.popen('mdadm -D ' + request.data['theRaidName'] + '|grep \'Raid Level :\' |awk -F\':\' \'{print $2}\'', "r")
            obj['raidLevel'] = result.readline().split('\n')[0]
            result.close()
            
            line = getAlineInFile(RAID_CONFIG_FILE, request.data['theRaidName'], 1).split('\n')[0].strip()#去掉每个字符串末尾的换行符,再去掉前边的空格
            childDevStr = line.split('=')[1]#去掉前缀‘devices=’,得到/dev/sda,/dev/sdc
            ChildDevs = childDevStr.split(',')# is a list ['/dev/sda', '/dev/sdb', '/dev/sdc']
            logger.debug(f'childDevs:{ChildDevs}')

            ChildDevsSize = []
            for ele in ChildDevs:
                result = os.popen('lsblk -o SIZE ' +  ele + ' -n -P |awk -F"=" \'NR==1 {print $2}\' |awk -F\'"\' \'{print $2}\'', "r")
                ChildDevsSize.append(result.readline().split('\n')[0])
                result.close()
            
            
            logger.debug(f'childDevsSize: {ChildDevsSize}')

            ChildStates = []
            for ele in ChildDevs:
                result = os.popen('mdadm -D ' + request.data['theRaidName'] + ' |grep ' + ele + ' |awk \'{print $(NR + 4)}\'', "r")
                ChildStates.append(result.readline().split('\n')[0])
                result.close()
            
            logger.debug(f'ChildStates:{ChildStates}')

            childInfo = []
            for index in range( len(ChildDevs) ):

                childInfo.append({'zone':ChildDevs[index], 'size':ChildDevsSize[index], 'type':ChildStates[index]})
                
            obj['raidChild'] = childInfo

            obj['freeZone'] = getFreeZoneFun()

            logger.debug(f'raidChild : {obj["raidChild"]}')
            logger.debug(f'freeZone : {obj["freeZone"]}')

            return JSONResponse(obj)

        except Exception as err:
            logger.error("get free zone list error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetFRaidDetailError")
            return JSONResponse(ret)
        


class addHostToRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidHostDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='热备盘列表'),
        },
        required=['raidName', 'raidHostDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug(request.data['raidName'] + " add host post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --add-spare"

            for ele in request.data['raidHostDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("add host cmd :" + cmd)

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("AddHostError")
                return JSONResponse(ret)

            fileLineList = getFilelines(RAID_CONFIG_FILE)

            os.system('mdadm -Dsv  > ' + RAID_CONFIG_FILE)#覆盖
            time.sleep(1)

            for line in fileLineList:
                if line.find(word) >= 0:
                    appendAWordInTheEndOfALine(RAID_CONFIG_FILE, line.split()[1], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": '添加热备盘成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("add host error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddHostError")
            return JSONResponse(ret)



class delHostFromRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidHostDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='热备盘列表'),
        },
        required=['raidName', 'raidHostDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        
        try:
            logger.debug(request.data['raidName'] + " remove host post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --remove"

            for ele in request.data['raidHostDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("remove host cmd :" + cmd)

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveHostError")
                return JSONResponse(ret)

            cmd = "mdadm --misc --zero-superblock --force "

            for ele in request.data['raidHostDevsName']:

                cmd = cmd + "  " + ele

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveHostError")
                return JSONResponse(ret)

            line = getAlineInFile(RAID_CONFIG_FILE, request.data['raidName'], 0)

            delLinesInFile(RAID_CONFIG_FILE, request.data['raidName'], 2)#delete the old record

            os.system('mdadm -Dsv  ' + request.data['raidName'] + '  >> ' + RAID_CONFIG_FILE)
            time.sleep(1)

            if line.find(word) >= 0:
                appendAWordInTheEndOfALine(RAID_CONFIG_FILE, request.data['raidName'], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": '删除热备盘成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("remove host error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("RemoveHostError")
            return JSONResponse(ret)



class removeDevFromRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidChildDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid活动子设备列表'),
        },
        required=['raidName', 'raidChildDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug(request.data['raidName'] + " remove child devs post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --fail"
            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveDevError")
                return JSONResponse(ret)

            cmd = "mdadm " + request.data['raidName'] + " --remove"
            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveDevError")
                return JSONResponse(ret)

            cmd = "mdadm  --misc --zero-superblock"
            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveDevError")
                return JSONResponse(ret)

            fileLineList = getFilelines(RAID_CONFIG_FILE)

            os.system('mdadm -Dsv  > ' + RAID_CONFIG_FILE)#覆盖
            time.sleep(1)

            for line in fileLineList:
                if line.find(word) >= 0:
                    appendAWordInTheEndOfALine(RAID_CONFIG_FILE, line.split()[1], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": '删除子设备成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("remove child devs error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("RemoveDevError")
            return JSONResponse(ret)




class faultyDevFromRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidChildDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid活动子设备列表'),
        },
        required=['raidName', 'raidChildDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug(request.data['raidName'] + " faulty child devs post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --fail"

            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("faulty child devs cmd :" + cmd)

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("FaultyDevError")
                return JSONResponse(ret)

            fileLineList = getFilelines(RAID_CONFIG_FILE)

            os.system('mdadm -Dsv  > ' + RAID_CONFIG_FILE)#覆盖
            time.sleep(1)

            for line in fileLineList:
                if line.find(word) >= 0:
                    appendAWordInTheEndOfALine(RAID_CONFIG_FILE, line.split()[1], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": 'faulty子设备成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("faulty child devs error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("FaultyDevError")
            return JSONResponse(ret)




class recoverFaultyDevFromRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidChildDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid faulty设备列表'),
        },
        required=['raidName', 'raidChildDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug(request.data['raidName'] + " recover faulty child devs post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --re-add"

            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("recover faulty child devs cmd :" + cmd)
            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RecoverFaultyDevError")
                return JSONResponse(ret)

            line = getAlineInFile(RAID_CONFIG_FILE, request.data['raidName'], 0)

            delLinesInFile(RAID_CONFIG_FILE, request.data['raidName'], 2)#delete the old record

            os.system('mdadm -Dsv  ' + request.data['raidName'] + '  >> ' + RAID_CONFIG_FILE)
            time.sleep(1)

            if line.find(word) >= 0:
                appendAWordInTheEndOfALine(RAID_CONFIG_FILE, request.data['raidName'], word)

            for ele in request.data['raidChildDevsName']:

                result = os.popen('mdadm -D ' + request.data['raidName'] + ' |grep ' + ele + ' |awk \'{print $(NR + 4)}\'', "r")
                status = result.readline().split('\n')[0]
                result.close()
                logger.debug('the recover faulty dev result:' + status)

                if status == 'faulty':
                    ret = get_error_result("DeviceOrResourceBusy")
                    return JSONResponse(ret)

            restartDevMonitor()

            ret = {"code": 0, "msg": '恢复faulty设备成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("recover faulty child devs error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("RecoverFaultyDevError")
            return JSONResponse(ret)



class removeFaultyDevFromRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidChildDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid faulty设备列表'),
        },
        required=['raidName', 'raidChildDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug('remove ' + request.data['raidName'] + " faulty devs post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --remove"

            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("remove faulty devs cmd :" + cmd)
            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveFaultyDevsError")
                return JSONResponse(ret)

            cmd = "mdadm --misc --zero-superblock --force "

            for ele in request.data['raidChildDevsName']:

                cmd = cmd + "  " + ele

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("RemoveFaultyDevsError")
                return JSONResponse(ret)

            line = getAlineInFile(RAID_CONFIG_FILE, request.data['raidName'], 0)

            delLinesInFile(RAID_CONFIG_FILE, request.data['raidName'], 2)#delete the old record

            os.system('mdadm -Dsv  ' + request.data['raidName'] + '  >> ' + RAID_CONFIG_FILE)
            time.sleep(1)

            if line.find(word) >= 0:
                appendAWordInTheEndOfALine(RAID_CONFIG_FILE, request.data['raidName'], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": '删除faulty设备成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("remove faulty devs error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("RemoveFaultyDevsError")
            return JSONResponse(ret)
 


class replaceChildDev(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'replaceChildDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid 活动子设备列表'),
            'replaceWithDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='raid 空闲子设备列表'),
        },
        required=['raidName', 'replaceChildDevsName', 'replaceWithDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug('replace ' + request.data['raidName'] + " child devs post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --manage " + request.data['raidName'] + " --replace"

            for ele in request.data['replaceChildDevsName']:

                cmd = cmd + "  " + ele

            cmd = cmd + " --with "

            for ele in request.data['replaceWithDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("replace child devs cmd :" + cmd)

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("ReplaceChildDevsError")
                return JSONResponse(ret)

            line = getAlineInFile(RAID_CONFIG_FILE, request.data['raidName'], 0)

            delLinesInFile(RAID_CONFIG_FILE, request.data['raidName'], 2)#delete the old record

            os.system('mdadm -Dsv  ' + request.data['raidName'] + '  >> ' + RAID_CONFIG_FILE)
            time.sleep(1)

            if line.find(word) >= 0:
                appendAWordInTheEndOfALine(RAID_CONFIG_FILE, request.data['raidName'], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": '替换子设备成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("replace child devs error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("ReplaceChildDevsError")
            return JSONResponse(ret)
        


class growUpRaid(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='raid的名字'),
            'raidChildDevNum': openapi.Schema(type=openapi.TYPE_INTEGER, description='raid扩容后的设备数量'),
            'growUpDevsName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='空闲设备列表'),
        },
        required=['raidName', 'raidChildDevNum', 'growUpDevsName'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug('grow ' + request.data['raidName'] + " post request")

            if theMaddmRaidUseToPysicalVolume(request.data['raidName']) == True:
                logger.debug(request.data['raidName'] + '被用来创建物理卷了')
                ret = get_error_result("RaidHadBeUsed")
                return JSONResponse(ret)

            cmd = "mdadm --grow " + request.data['raidName'] + " --raid-disks " + str(request.data['raidChildDevNum']) + " --add "

            for ele in request.data['growUpDevsName']:

                cmd = cmd + "  " + ele

            logger.debug("grow up raid cmd :" + cmd)

            status, res = runCmdAndGetLog(cmd)
            if status != 0:
                ret = get_error_result("GrowUpRaidError")
                return JSONResponse(ret)

            line = getAlineInFile(RAID_CONFIG_FILE, request.data['raidName'], 0)

            delLinesInFile(RAID_CONFIG_FILE, request.data['raidName'], 2)#delete the old record

            os.system('mdadm -Dsv  ' + request.data['raidName'] + '  >> ' + RAID_CONFIG_FILE)
            time.sleep(1)

            if line.find(word) >= 0:
                appendAWordInTheEndOfALine(RAID_CONFIG_FILE, request.data['raidName'], word)

            restartDevMonitor()

            ret = {"code": 0, "msg": 'raid扩容成功'}
            return JSONResponse(ret)

        except Exception as err:
            logger.error("grow up raid error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GrowUpRaidError")
            return JSONResponse(ret)
 


class getMailInfos(APIView):

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("get mail info post request")

            mailList = getMails()

            logger.debug('the mail list: ' + str(mailList))
    
            tableData = getMailsConfig()

            logger.debug('the mail config: ' + str(tableData))

            obj = {}

            obj['mailList'] = mailList
            obj['tableData'] = tableData

            return JSONResponse(obj)

        except Exception as err:
            logger.error("get mail info error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetMailInfoError")
            return JSONResponse(ret)


class updateMails(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_ARRAY,
        items=openapi.Items(type=openapi.TYPE_STRING, description='邮箱字符串'),
        required=[''],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("update mail info post request")

            oldMailList = getMails()#先获取老的邮件列表

            #提取新添加的或者删除的邮箱
            addMailList = []
            delMailList = []
            isAddAction = False

            for oldMail in oldMailList:

                find = 0
                for newMail in request.data:

                    if oldMail == newMail:
                        find = 1
                        break

                if find == 0:#not find,mean the mail delete
                    delMailList.append(oldMail)

            if len(delMailList) == 0:#no mail to delete, mean is a add action

                isAddAction = True
                for newMail in request.data:

                    find = 0
                    for oldMail in oldMailList:
                
                        if  newMail == oldMail:
                            find = 1
                            break

                    if find == 0:#not find,mean the mail delete
                        addMailList.append(newMail)

                logger.debug(f'add mail:{addMailList}')

            else:
                logger.debug(f'del mail:{delMailList}')

            writeMails(request.data)#再更新邮箱记录文件

            configTableData = getMailsConfig()

            if isAddAction == True:

                for ele in configTableData:

                    if ele['status'] == True:

                        for mail in addMailList:

                            cmd = 'mdadm --monitor ' + ele['raidName'] + ' --mail ' + mail + '&'
                            logger.debug(f'add monitor thread cmd:{cmd}')
                            os.system(cmd)

            else:

                for ele in configTableData:

                    if ele['status'] == True:

                        pid = ''
                        for mail in delMailList:

                            cmd = 'ps -ef |grep "mdadm --monitor ' + ele['raidName'] + ' --mail ' + mail + '" |awk \'NR==1{print $2}\''
                            result = os.popen(cmd, "r")
                            pidLine = result.readline()
                            result.close()
                            if len(pidLine) > 0:
                                pid = pidLine.split('\n')[0]
                                cmd = 'kill ' + pid
                                logger.debug(f'del monitor thread cmd:{cmd}')
                                os.system(cmd)

                            else:
                                ret = get_error_result('UpdateMailInfoError')
                                return JSONResponse(ret)


            ret = get_error_result('Success')
            return JSONResponse(ret)

        except Exception as err:
            logger.error("update mail info error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("UpdateMailInfoError")
            return JSONResponse(ret)
        

class updateMailsConfig(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_ARRAY,
        items=openapi.Items(
            type=openapi.TYPE_OBJECT, 
            properties={
            'status': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='是否监听'),
            'raidName': openapi.Schema(type=openapi.TYPE_STRING, description='阵列名字'),
            },
            required=['status', 'raidName'],),
        required=[''],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("update mail config post request")

            theOperatorRaid = []

            oldMailConfig = getMailsConfig()

            for oldEleObj in oldMailConfig:

                for newEleObj in  request.data:

                    if oldEleObj['raidName'] == newEleObj['raidName']:
                        if oldEleObj['status'] == newEleObj['status']:
                            pass
                        else:
                            theOperatorRaid.append({'status': newEleObj['status'], 'raidName': newEleObj['raidName']})
                        break

            writeailsConfig(request.data)

            for obj in theOperatorRaid:

                if obj['status'] == True:#开启监控
                    startOneRaidMonitor(obj['raidName'])

                else:
                    stopOneRaidMonitor(obj['raidName'])

            ret = get_error_result('Success')
            return JSONResponse(ret)

        except Exception as err:
            logger.error("update mail config error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("UpdateMailConfigError")
            return JSONResponse(ret)
        



