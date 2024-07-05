#update record:2023-12-28



from operator import truediv
import os
import sys
import traceback
import logging
from django.http import Http404, HttpResponseServerError
from web_manage.cluster.models import ClusterNode
from web_manage.common.http import peer_post
from rest_framework.views import APIView
from web_manage.common.utils import JSONResponse, WebPagination, get_error_result
from web_manage.store.iscsi.iscsiSrv.models import tgtdAccount
from web_manage.admin.serializers import OperationLogSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from web_manage.common.cmdutils import run_cmd

logger = logging.getLogger(__name__)

DETAIL_PRINT_SWITCH = False
CONFIG_FILE_DIR = '/etc/tgt/conf.d/'
DEFAULT_ISCSI = 'default-driver iscsi'

def checkTgtdServerOnline():

    status, line = run_cmd('systemctl status tgtd |grep Active |awk \'{print $2}\'')
    logger.debug(f'tgtd 服务状态:{line}')
    
    if status == 0:
        if line != 'active':#没有这个服务
            return False
        else:
            return True
    else:
        return False
    

#获取所有target中最大的id
def getTheMaxTargetId():

    numberIds = []
    result = os.popen('tgtadm -L iscsi -m target -o show |grep "Target" |awk -F":" \'{print $1}\' |awk \'{print $2}\'', "r")
    allIds = result.readlines()
    result.close()
    if len(allIds) > 0:
        for ele in allIds:
            numberIds.append(int(ele.split('\n')[0]))

        theMaxNumber = 0
        for ele in numberIds:
            if ele > theMaxNumber:
                theMaxNumber = ele

        return theMaxNumber

    else:
        return 0

#获取指定target所有lun中最大的id
def getSpecificTargetMaxLunId(iqn):
    
    result = os.popen('tgtadm -L iscsi -m target -o show', "r")
    records = result.readlines()
    result.close()

    find = False

    index = 0
    if len(records) > 0:
        for index in range(len(records)):
            if records[index].find(iqn) != -1:
                find = True
                break;
    
    if find == False:
        return 0

    lunsIdList =  []
    while True:
        if records[index].find('LUN information:') != -1:

            index = index + 1#goto lun first line
            while True:
                if index >= len(records) or records[index].find('Account information:') != -1:#if find the 'Account information:' or in the end of records, then break while
                    break

                if records[index].find('LUN:') != -1:#a lun
                    lunsIdList.append(int(records[index].split(': ')[1].split('\n')[0]))
                    index = index + 13

                index = index + 1

            break
        else:
            index = index + 1

    if len(lunsIdList) <= 0:
        return 0
    else:
        theMaxLunId = 0
        for ele in lunsIdList:
            if ele > theMaxLunId:
                theMaxLunId = ele
        
        return theMaxLunId


#get tgt all accounts
def getAllAcountsList():
    accountList = []
    allUserRecord = tgtdAccount.objects.all()
    for ele in allUserRecord:
        accountList.append(ele.user)

    return accountList

#get spcefic target Acl list by target tid
def getTargetAclsStringListByTid(tid):
    result = os.popen('tgtadm -L iscsi -m target -o show', "r")
    records = result.readlines()
    result.close()

    find = False
    
    index = 0
    if len(records) > 0:
        for index in range(len(records)):
            if records[index].find("Target " + str(tid)) != -1:
                find = True
                break;
    #print('the target ' + str(tid) + ' line--> ' +  records[index].split('\n')[0])
    if find == False:
        return []

    aclList =  []
    while True:
        if records[index].find('ACL information:') != -1:

            index = index + 1#goto ACL first line
            while True:
                if index >= len(records) or records[index].find('Target') != -1:#if find next target or in the end of records, then break while
                    break
                
                aclList.append(records[index].split()[0])
        
                index = index + 1

            break
        else:
            index = index + 1

    if DETAIL_PRINT_SWITCH:
        logger.debug('Target ' + str(tid) +' ACL List--> ' + str(aclList))
    return aclList
            
#get spcefic target Account list by target iqn
def getTargetAccountsStringListByIQN(iqn):
    
    configName = getSpecificTargetConfigFileName(iqn)

    file = open(configName, 'r')
    allLines = file.readlines()
    file.close()

    accountList = []

    for line in allLines:
        if line.find('incominguser') != -1:
            user = line.split()[1]
            accountList.append(user)

    return accountList
 
#get spcefic target Lun obj list by target tid
def getTargetLunsObjListByTid(tid):
    result = os.popen('tgtadm -L iscsi -m target -o show', "r")
    records = result.readlines()
    result.close()
    
    find = False

    index = 0
    if len(records) > 0:
        for index in range(len(records)):
            if records[index].find("Target " + str(tid)) != -1:
                find = True
                break;
    
    if find == False:
        return []
    #print('the target ' + str(tid) + ' line--> ' +  records[index].split('\n')[0])

    lunsObjList =  []
    while True:
        if records[index].find('LUN information:') != -1:

            index = index + 1#goto lun first line
            while True:
                if index >= len(records) or records[index].find('Account information:') != -1:#if find the 'Account information:' or in the end of records, then break while
                    break

                if records[index].find('LUN:') != -1:#a lun
                    lunObj = {}
                    lunObj['lun']               = records[index].split(': ')[1].split('\n')[0]
                    lunObj['type']              = records[index + 1].split(': ')[1].split('\n')[0]
                    lunObj['scsi_id']           = records[index + 2].split(': ')[1].split('\n')[0]
                    lunObj['scsi_sn']           = records[index + 3].split(': ')[1].split('\n')[0]
                    lunObj['size']              = records[index + 4].split(',')[0].split(': ')[1]
                    lunObj['online']            = records[index + 5].split(': ')[1].split('\n')[0]
                    lunObj['removable_media']   = records[index + 6].split(': ')[1].split('\n')[0]
                    lunObj['prevent_removal']   = records[index + 7].split(': ')[1].split('\n')[0]
                    lunObj['readOnly']          = records[index + 8].split(': ')[1].split('\n')[0]
                    lunObj['swp']               = records[index + 9].split(': ')[1].split('\n')[0]
                    lunObj['thin_provisioning'] = records[index + 10].split(': ')[1].split('\n')[0]
                    lunObj['back_store_type']   = records[index + 11].split(': ')[1].split('\n')[0]
                    lunObj['back_store_path']   = records[index + 12].split(': ')[1].split('\n')[0]
                    lunObj['back_store_flags']  = records[index + 13].split(': ')[1].split('\n')[0]

                    lunsObjList.append(lunObj)
                    index = index + 13

                index = index + 1

            break
        else:
            index = index + 1

    if DETAIL_PRINT_SWITCH:
        logger.debug('Target ' + str(tid) +' Lun Obj List--> ' + str(lunsObjList))
    return lunsObjList

#get spcefic target information by target tid
def getTargetMaxConnectsByTid(tid):
    result = os.popen('tgtadm -L iscsi -m target -o show -t ' + str(tid), "r")
    keyValueList = result.readlines()
    result.close()
    for keyValue in keyValueList:
        if keyValue.find('MaxConnections') != -1:
            if DETAIL_PRINT_SWITCH:
                logger.debug('Target ' + str(tid) + ' max connect--> ' + keyValue.split('=')[1].split('\n')[0])
            return keyValue.split('=')[1].split('\n')[0]

#get spcefic invalid target Lun obj list by target iqn
def getInvalidTargetLunListByIQN(iqn):

    lunsObjList = []

    configName = getSpecificTargetConfigFileName(iqn)
    if len(configName) <= 0:
        return []
    
    file =open(configName, "r")
    allLines = file.readlines()
    file.close()

    lunId = 1
    for line in allLines:
        if line.find('backing-store') != -1:
            dev = line.split()[1].split('\n')[0]
            lunObj = {}
            lunObj['lun']               = lunId
            lunObj['type']              = 'disk'
            lunObj['scsi_id']           = ""
            lunObj['scsi_sn']           = ''
            lunObj['size']              = '未知'
            lunObj['online']            = 'No'
            lunObj['removable_media']   = ''
            lunObj['prevent_removal']   = ''
            lunObj['readOnly']          = ''
            lunObj['swp']               = ''
            lunObj['thin_provisioning'] = ''
            lunObj['back_store_type']   = 'rdwr'
            lunObj['back_store_path']   = dev
            lunObj['back_store_flags']  = ''

            lunsObjList.append(lunObj)
            lunId = lunId + 1

    return lunsObjList

def getTargetAclsStringListByIqn(iqn):

    AclsList = []

    configName = getSpecificTargetConfigFileName(iqn)
    if len(configName) <= 0:
        return []
    
    file =open(configName, "r")
    allLines = file.readlines()
    file.close()

    for line in allLines:
        if line.find('initiator-address') != -1:
            AclsList.append(line.split()[1].split('\n')[0])

    return AclsList


def getScsiAllInfomation():
    scsi = {}
    
    scsi['targetObjList'] = []
    scsi['allAccountStringList'] = getAllAcountsList()
    allConfigNameList = getAllTargetConfigFileNameList()
    for configName in allConfigNameList:
        theTarget = {}
        iqn = ''
        valid = True
        active = True
        if configName.find('.conf') != -1:
            iqn = configName.split('.conf')[0].split('/')[4]
            
        elif configName.find('.invalid') != -1:
            iqn = configName.split('.invalid')[0].split('/')[4]
            valid = False

        elif configName.find('.inactive') != -1:
            iqn = configName.split('.inactive')[0].split('/')[4]
            active = False

        else:
            logger.debug('------>无效配置文件:' + configName)
            continue
        

        theTarget['targetIQN'] = iqn

        if valid and active:#配置文件是.conf结尾的
            #获取该target的id
            result = os.popen('tgtadm -L iscsi -m target -o show |grep ' + iqn + ' |awk \'{print $2}\' |awk -F":" \'{print $1}\'')
            allLines = result.readlines()
            result.close()
            if len(allLines) > 0:
                tid = allLines[0].split('\n')[0]
            else:
                continue

            theTarget['tid'] = tid
            theTarget['status'] = 'valid'
            theTarget['activeStatus'] = 'active'
            theTarget['LunsObjList'] = getTargetLunsObjListByTid(tid)
            theTarget['AclsStringList'] = getTargetAclsStringListByTid(tid)
            theTarget['maxConnects'] = getTargetMaxConnectsByTid(tid)

        else :
            theTarget['tid'] = '-1'

            if valid == True:
                theTarget['status'] = 'valid'
            else:
                theTarget['status'] = 'invalid'

            if active == True:
                theTarget['activeStatus'] = 'active'
            else:
                theTarget['activeStatus'] = 'inactive'

            theTarget['LunsObjList'] = getInvalidTargetLunListByIQN(iqn)
            theTarget['AclsStringList'] = getTargetAclsStringListByIqn(iqn)
            theTarget['maxConnects'] = ''

        theTarget['AccountsStringList'] = getTargetAccountsStringListByIQN(iqn)

        scsi['targetObjList'].append(theTarget)

    return scsi


class getTheScsiAllInformation(APIView):

    @swagger_auto_schema(None)

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("get iscsi all information post request")

            scsi = {}

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return JSONResponse(ret)

            scsi = getScsiAllInfomation()
            ret = {}

            #ret['msg'] = "获取所有ISCSI信息成功"
            #ret['data'] = scsi
            ret = get_error_result("Success", scsi)
            return JSONResponse(ret)

        except Exception as err:
            logger.error("get iscsi all information error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetIscsiAllInfoError")
            return JSONResponse(ret)
        

def getFreeResourceForIscsiFun():

    result = os.popen('lvscan |awk \'{print $2}\' |awk -F"\'" \'{print $2}\'', "r")
    lvmPath = result.readlines()
    result.close()

    result = os.popen('lvscan |awk -F\'[\' \'{print $2}\' |awk -F\']\' \'{print $1}\'', "r")
    lvmSize = result.readlines()
    result.close()

    index = 0
    while True:

        if(index >= len(lvmPath)):
            break
        
        result = os.popen('lsblk ' + lvmPath[index].split('\n')[0] + '|awk \'NR!=1{print $7}\'', "r")
        mountDir = result.readlines()
        result.close()
        pathLen = len(mountDir[0].split('\n')[0])
        logger.debug(lvmPath[index].split('\n')[0] + ' mount path: ' + mountDir[0].split('\n')[0] + ' ,the path length: ' +  str(pathLen)) 
        
        if(len(mountDir[0].split('\n')[0]) != 0):#had by mountted
           del lvmPath[index]
           del lvmSize[index]
           index = index - 1

        index = index + 1 

    logger.debug('after filter lvmPath list:' + str(lvmPath))

    index = 0
    freeResourcesList = []
    for path in lvmPath:
        freeResourcesList.append({'devName':path.split('\n')[0], 'devType':'lvm', 'devSize':lvmSize[index].split('\n')[0]})
        index = index + 1

    return freeResourcesList


class getFreeResourcesForScsi(APIView):

    @swagger_auto_schema(None)

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("get free resource for iscsi post request")

            freeResourcesList = getFreeResourceForIscsiFun()
            logger.debug('update the free lvm:')
            logger.debug(freeResourcesList)

            #ret['data'] = freeResourcesList
            ret = get_error_result("Success", freeResourcesList)
            return JSONResponse(ret)

        except Exception as err:
            logger.error("get free resource for iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetFreeResourceForIscsiError")
            return JSONResponse(ret)
        


def getSpecificTargetTgtaccountInfo(target):
    
    st_index = -1
    end_index = -2
    configLines = []

    res = os.popen('tgt-admin -s')
    result = res.readlines()
    res.close()

    for index in range(len(result)):
        if result[index].find(target) != -1:
            st_index = index
        
        elif result[index].find('Target') != -1 and st_index != -1:
            end_index = index#
            configLines = result[st_index:end_index]#切片
            break
        
        elif index == len(result) - 1 and st_index != -1:
            end_index = index + 1#结束位置的下一个位置
            configLines = result[st_index:end_index]#切片
            break

        else:
            pass

    logger.debug(f'------>configLines: {configLines}')
    
    accountList = []

    theAccountIndex = -1
    if len(configLines) > 0:
        for index in range(len(configLines)):
            if configLines[index].find('ACL information:') != -1 and index + 1 < len(configLines):
                theAccountIndex = index + 1
                break

    if theAccountIndex != -1:
        while theAccountIndex < len(configLines):
            account =  configLines[theAccountIndex].split()[0].split('\n')[0]
            accountList.append(account)
            theAccountIndex = theAccountIndex + 1

    return accountList


def getAllTargetConfigFileNameList():

    result = os.popen('ls -l ' + CONFIG_FILE_DIR + '|awk \'NR>1{print $NF}\'')
    lines = result.readlines()
    result.close()
    
    for index in range(len(lines)):
        lines[index] = lines[index].split('\n')[0]
        lines[index] = CONFIG_FILE_DIR + lines[index]

    return lines


def getSpecificTargetConfigFileName(target):

    AllTargetConfigFileNameList = getAllTargetConfigFileNameList()
    for fileName in AllTargetConfigFileNameList:
        name = os.path.basename(fileName)
        theIqn = ''
        if name.find('.conf') != -1:
            theIqn = name.split(".conf")[0]
        elif name.find('.invalid') != -1:
            theIqn = name.split(".invalid")[0]
        elif name.find('.inactive') != -1:
            theIqn = name.split(".inactive")[0]
        else:
            continue
        logger.debug(f'获取指定target的配置文件名:{name}, iqn：{theIqn}')
        if theIqn == target:
            return fileName
    return ''    
    


def existDefaultIscsi(allConfigFileNameList):
    
    ret = False

    if len(allConfigFileNameList) > 0:
        for fileName in allConfigFileNameList:
        
            file = open(fileName, 'r')
            allLines = file.readlines()
            for line in allLines:
                if line.find(DEFAULT_ISCSI) != -1:#find
                    ret = True
                    file.close()
                    return ret
            file.close()

    return ret

#创建一个新的target配置文件
def createNewTargetConfigFile(target):

    allConfigFileNameList = getAllTargetConfigFileNameList()

    file = open(f'{CONFIG_FILE_DIR}{target}.conf', "w")

    if existDefaultIscsi(allConfigFileNameList) == False:
        file.write(f'{DEFAULT_ISCSI}\n')

    file.write(f'<target {target}>\n')
    file.write('</target>\n')
    file.close()



class createTarget(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='将要创建的iscsi的id'),
            'target': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili')
        },
        required=['tid', 'target'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("create Traget post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                logger.debug(f'######################peerStatus:{peerStatus}###########################')

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.dealCmdLocal(request)
                else:
                    ret = self.dealCmdPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.dealCmdLocal(request)
                    logger.debug(f'######################双端操作###########################')
            else:
                ret = self.dealCmdLocal(request)

            return JSONResponse(ret)

        except Exception as err:
            logger.error("create target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddNewTargetAccountError")
            return JSONResponse(ret)
        
    def dealCmdLocal(self, request):

        ret = {}

        try:

            #tid = request.data.get('tid')#string
            tid = str(getTheMaxTargetId() + 1)
            target = request.data.get('target')#string

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            allFileNameList = getAllTargetConfigFileNameList()
            for fileName in allFileNameList:
                if fileName.find(target) != -1:
                    ret = get_error_result("TargetHadExist")
                    return ret

            createNewTargetConfigFile(target)

            result = run_cmd('tgtadm -L iscsi -m target -o new -t ' + tid + ' -T ' + target)
            if result[0] != 0:
                ret = get_error_result("CreateTargetFail")
                return ret

            result = run_cmd('tgtadm -L iscsi -m target -o bind -t ' + tid + ' -I ALL')
            if result[0] != 0:
                ret = get_error_result("CreateTargetFail")
                return ret

            # ret['code'] = 0
            # ret['msg'] = '创建 target：'+ target + '成功'
            kwargs = {
                'msg': '创建 target：'+ target + '成功'
            }
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("create target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddNewTargetAccountError")
            return ret

    def dealCmdPeer(self, request):
        try:
            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            requestEnd = 'backEnd'

            newRequest = {
                'requestEnd':requestEnd,
                'tid' : tid,
                'target' : target
            }

            return peer_post("/store/iscsiSrv/createTarget/", newRequest)

        except Exception as err:
            logger.error("create target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddNewTargetAccountError")
            return ret    


def getLinkIpStr(iqn):

    str = ""

    allConfigDetail = os.popen('tgt-admin -s', "r").readlines()

    index = 0
    lineCnt = len(allConfigDetail)
    while index < lineCnt:
        if allConfigDetail[index].find(iqn) != -1:

            while index < lineCnt:

                if allConfigDetail[index].find('LUN information:') != -1:
                    return str
                
                if allConfigDetail[index].find('IP Address:') != -1:
                    str = str + allConfigDetail[index].split('IP Address:')[1]

                index = index + 1


        index = index + 1

    return str

        



class deleteTarget(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='将要删除的iscsi的id'),
            'target': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili')
        },
        required=['tid', 'target'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("delete Traget post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.dealCmdLocal(request)
                else:
                    ret = self.dealCmdPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.dealCmdLocal(request)
            else:
                ret = self.dealCmdLocal(request)

            return JSONResponse(ret)

        except Exception as err:
            logger.error("delete target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteTartgetCmdError")
            return JSONResponse(ret)
        
    def dealCmdLocal(self, request):

        ret = {}

        try:

            if checkTgtdServerOnline() == False:

                get_error_result("IscsiServerNotOnline")
                return ret

            tid = request.data.get('tid')#string
            target = request.data.get('target')#string

            ipStr = getLinkIpStr(target)
            if len(ipStr) != 0:
                kwargs = {
                        'ipStr': ipStr
                    }
                ret = get_error_result("CurTargetHadLink", data=None, **kwargs)
                return ret
            
            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("DeleteTartgetCmdError")
                return ret
            
            os.system(f'rm -f {configFileName}')

            allConfigFileNameList = getAllTargetConfigFileNameList()
            if existDefaultIscsi(allConfigFileNameList) == False:#此时所有配置文件中都没有默认iscsi

                if len(allConfigFileNameList) > 0:
                    file = open(allConfigFileNameList[0], "r")#修改第一个配置文件，将对应的target改成默认iscsi
                    allLines = file.readlines()
                    file.close()
                    allLines.insert(0, f'{DEFAULT_ISCSI}\n')
                    file = open(allConfigFileNameList[0], "w")
                    file.writelines(allLines)
                    file.close

            status, res = run_cmd('tgt-admin -s |grep ' + target + ' |awk -F":" \'{print $1}\' |awk \'{print $2}\'')
            if len(res) > 0:
                tid = res.split('\n')[0]
                run_cmd('tgtadm -L iscsi -m target -o delete --force -t ' + tid )
                                    
            # ret['code'] = 0
            # ret['msg'] = '删除 target 成功'

            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("delete target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteTartgetCmdError")
            return ret

    def dealCmdPeer(self, request):
        try:
            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            requestEnd = 'backEnd'

            newRequest = {
                'requestEnd':requestEnd,
                'tid' : tid,
                'target' : target
            }

            return peer_post("/store/iscsiSrv/deleteTarget/", newRequest)

        except Exception as err:
            logger.error("delete target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteTartgetCmdError")
            return ret    



class setPermitHostAccess(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='iscsi的id'),
            'target': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili'),
            'deleteHostList': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='需要删除原有的host列表'),
            'addHostList': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='需要新添加的host列表'),
        },
        required=['tid', 'target, deleteHostList, addHostList'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("set permit Host Access post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.dealCmdLocal(request)
                else:
                    ret = self.dealCmdPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.dealCmdLocal(request)
            else:
                ret = self.dealCmdLocal(request)

            return JSONResponse(ret)

        except Exception as err:
            logger.error("set permit host error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("SetPermitHostAccessError")
            return JSONResponse(ret)
        
    def dealCmdLocal(self, request):

        ret = {}

        try:

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            tid = request.data.get('tid')#'string'
            target = request.data.get('target')#string
            addHostList = request.data.get('addHostList')#需要新添加的host列表(string)
                
            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("SetPermitHostAccessError")
                return ret
            
            file = open(configFileName, "r")
            allLines = file.readlines()
            file.close()
            
            index = 0
            while True:
                if index >= len(allLines):
                    break

                if allLines[index].find('initiator-address') != -1 or allLines[index].find('initiator-name ALL') != -1:#删除已存在的ip
                    del allLines[index]
                    index = index - 1

                index = index + 1
                
            file = open(configFileName, "w")
            if len(addHostList) > 0:
                for host in addHostList:
                    allLines.insert(len(allLines) - 1, f'\tinitiator-address {host}\n')#在最后一行之前插入ip
            # else:
            #     allLines.insert(len(allLines) - 1, '\tinitiator-name ALL\n')#在最后一行之前插入ip

            file.writelines(allLines)
            file.close()

            deleteHostList = getSpecificTargetTgtaccountInfo(target)#需要删除原有的host列表(string)

            logger.debug(f'\n\n---------->the delete host: {deleteHostList}')
            
            for host in deleteHostList:
                result = run_cmd('tgtadm -L iscsi -m target -o unbind -t ' + tid + ' -I ' + host)
                if result[0] != 0:
                    ret = get_error_result("SetPermitHostAccessError")
                    return ret
                
            if len(addHostList) > 0:#非匿名访问
                for host in addHostList:
                    result = run_cmd('tgtadm -L iscsi -m target -o bind -t  ' + tid + ' -I ' + host)
                    if result[0] != 0:
                        ret = get_error_result("SetPermitHostAccessError")
                        return ret
            else:#匿名访问
                result = run_cmd('tgtadm -L iscsi -m target -o bind -t  ' + tid + ' -I ALL')

            # ret['code'] = 0
            # ret['msg'] = '设置允许访问 target 的主机成功'
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("set permit host error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("SetPermitHostAccessError")
            return ret

    def dealCmdPeer(self, request):
        try:
            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            #deleteHostList = request.data.get('deleteHostList')#需要删除原有的host列表(string)
            addHostList = request.data.get('addHostList')#需要新添加的host列表(string)
            requestEnd = 'backEnd'

            newRequest = {
                'requestEnd':requestEnd,
                'tid' : tid,
                'target' : target,
                #'deleteHostList' : deleteHostList,
                'addHostList' : addHostList,
            }

            return peer_post("/store/iscsiSrv/setPermitHostAccess/", newRequest)

        except Exception as err:
            logger.error("set permit host error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("SetPermitHostAccessError")
            return ret    



class deleteTargetLun(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='iscsi的id'),
            'target': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili'),
            'lun': openapi.Schema(type=openapi.TYPE_STRING, description='lun 在 target中对应的id' ),
            'lunDevPath': openapi.Schema(type=openapi.TYPE_STRING, description='被添加为 lun 设备的绝对路径' )
        },
        required=['tid', 'target', 'lun', 'lunDevPath'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("delete Traget lun post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.dealCmdLocal(request)
                else:
                    ret = self.dealCmdPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.dealCmdLocal(request)
            else:
                ret = self.dealCmdLocal(request)

            return JSONResponse(ret)

        except Exception as err:
            logger.error("delete target lun error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteTartgetLunCmdError")
            return JSONResponse(ret)
        
    def dealCmdLocal(self, request):

        ret = {}

        try:

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            lun = request.data.get('lun')#string
            lunDevPath = request.data.get('lunDevPath')#string

            ipStr = getLinkIpStr(target)
            if len(ipStr) != 0:
                kwargs = {
                        'ipStr': ipStr
                    }
                ret = get_error_result("CurTargetHadLink", data=None, **kwargs)
                return ret

            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("DeleteTartgetLunCmdError")
                return ret
            
            file = open(configFileName, "r")
            allLines = file.readlines()
            file.close()

            index = 0
            while True:
                if index >= len(allLines):
                    break

                if allLines[index].find(lunDevPath) != -1:
                    del allLines[index]
                    index = index - 1

                index = index + 1

            file = open(configFileName, "w")
            file.writelines(allLines)
            file.close()

            result = run_cmd('tgtadm -L iscsi -m logicalunit -o delete -t ' + str(tid) + ' -l ' + str(lun))#lun存不存在都不影响

            # ret['code'] = 0
            # ret['msg'] = '删除 target lun 成功'
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("delete target lun error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteTartgetLunCmdError")
            return ret

    def dealCmdPeer(self, request):
        try:
            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            lun = request.data.get('lun')#string
            lunDevPath = request.data.get('lunDevPath')#string
            
            requestEnd = 'backEnd'

            newRequest = {
                'requestEnd':requestEnd,
                'tid' : tid,
                'target' : target,
                'lun' : lun,
                "lunDevPath" : lunDevPath
            }

            return peer_post("/store/iscsiSrv/deleteTargetLun/", newRequest)

        except Exception as err:
            logger.error("delete target lun error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteTartgetLunCmdError")
            return ret    



class addTargetLun(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='iscsi的id'),
            'target': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili'),
            'lunObjList': openapi.Schema(type=openapi.TYPE_ARRAY, 
                                        items=openapi.Items(type=openapi.TYPE_OBJECT, 
                                        properties={
                                            'newlunid': openapi.Schema(type=openapi.TYPE_NUMBER, description='该target中未被占用的lun id'),
                                            'lunPath': openapi.Schema(type=openapi.TYPE_STRING, description='添加为lun的设备的绝对路径,像：/dev/drbd0'),
                                            'disk': openapi.Schema(type=openapi.TYPE_STRING, description='添加为lun的设备的复制逻辑卷对应的lvm的绝对路径,像：/dev/vg1/lv1'),
                                        },
                                        required=['newlunid', 'lunPath', 'disk'],
                                        ))

        },
        required=['tid', 'target', 'lunObjList'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("add Traget lun post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.dealCmdLocal(request)
                else:
                    ret = self.dealCmdPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.dealCmdLocal(request)
            else:
                ret = self.dealCmdLocal(request)

            return JSONResponse(ret)

        except Exception as err:
            logger.error("add target lun error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddTartgetLunCmdError")
            return JSONResponse(ret)
        
    def dealCmdLocal(self, request):

        ret = {}

        try:

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            lunObjList = request.data.get('lunObjList')#{newlunid : 12, lunPath: '/dev/drbd0', disk: '/dev/vg1/lv1'} int string
            lunObjListBackUp = [] 

            for lun in lunObjList:
                lunObjListBackUp.append(lun)

            secondaryCopyLvmFlag = False

            copyLvmDevList = []
            for lun in lunObjList:
                if lun['disk'] != None and len(lun['disk']) > 0:
                    baseName = os.path.basename(lun['disk'])
                    logger.debug(f'复制逻辑卷的lvm:{baseName}')
                    status, outPut = run_cmd(f'drbdadm role {baseName}')
                    if status != 0:#该设备不存在
                        ret = get_error_result("ParameterError")
                        return ret
                    else:
                        if outPut == 'Secondary':#从端
                            copyLvmDevList.append(lun["lunPath"])
                            secondaryCopyLvmFlag = True
                            continue
                
                status, outPut = run_cmd(f'ls {lun["lunPath"]}')
                if status != 0:#该设备不存在,可能是从端
                    index = 0
                    for ele in lunObjListBackUp:
                        if ele["lunPath"] == lun["lunPath"]:
                            del lunObjListBackUp[index]
                            break
                        index = index + 1

                    continue

                newlunid = getSpecificTargetMaxLunId(target) + 1

                result = run_cmd('tgtadm -L iscsi -m logicalunit -o new -t ' + tid + ' -l ' + str(newlunid) + ' -b ' + lun["lunPath"])
                if result[0] != 0:
                    ret = get_error_result("AddTartgetLunCmdError")
                    return ret

            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("AddTartgetLunCmdError")
                return ret
            
            file = open(configFileName, "r")
            allLines = file.readlines()
            file.close()

            os.system(f'rm -fr {configFileName}')

            if secondaryCopyLvmFlag == True:#要重命名配置文件为iqn.2023-12.node2.iscsi.com:ming.invalid结尾
                configFileName = CONFIG_FILE_DIR + target + '.invalid'

            file = open(configFileName, "w")
            for lun in lunObjListBackUp:
                exist = False
                for line in allLines:
                    if line.find(lun["lunPath"]) != -1:#原来配置文件中存在该lun
                        exist = True
                        break
                
                if exist == False:
                    allLines.insert(len(allLines) - 1, f'\tbacking-store {lun["lunPath"]}\n') 
                        
            file.writelines(allLines)
            file.close()

            msg = ''
            # ret['code'] = 0
            if secondaryCopyLvmFlag == True:
                msg = '添加 lun 到配置文件中成功, 但从机用复制逻辑卷:'
                for ele in copyLvmDevList:
                    msg = msg + ele + '; '
                msg = msg +' 作为逻辑单元只有当从机变为主机时才能生效'
            else:
                msg = '添加 target lun 成功'

            kwargs = {
                'msg' : msg
            }

            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("add target lun error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddTartgetLunCmdError")
            return ret

    def dealCmdPeer(self, request):
        try:
            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            lunObjList = request.data.get('lunObjList')#{newlunid : 12, lunPath: '/dev/vg1/lv1'} int string
            requestEnd = 'backEnd'

            newRequest = {
                'requestEnd':requestEnd,
                'tid' : tid,
                'target' : target,
                'lunObjList' : lunObjList
            }

            return peer_post("/store/iscsiSrv/addTargetLun/", newRequest)

        except Exception as err:
            logger.error("add target lun error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddTartgetLunCmdError")
            return ret    


#只添加账户到特定的target
class addTargetAccount(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='iscsi的id'),
            'target': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili'),
            'accountList': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='账户列表' ),
        },
        required=['tid', 'target', 'accountList'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("add Target account post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.dealCmdLocal(request)
                else:
                    ret = self.dealCmdPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.dealCmdLocal(request)
            else:
                ret = self.dealCmdLocal(request)

            return JSONResponse(ret)

        except Exception as err:
            logger.error("add account to target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddTargetAccountCmdError")
            return JSONResponse(ret)
        
    def dealCmdLocal(self, request):

        ret = {}

        try:

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            accountList = request.data.get('accountList')#string
            if accountList == None:
                ret = get_error_result("ParameterError")
                return ret

            noLimit = False
            if len(accountList) == 0:
                noLimit = True

            addList = []

            allAccountList = getAllAcountsList()

            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("ParameterError")
                return ret
            
            file = open(configFileName, "r")
            allLines = file.readlines()
            file.close()

            index  = 0
            while True:

                if index >= len(allLines):
                    break
            
                if allLines[index].find('incominguser') != -1:
                    del allLines[index]
                    index = index - 1

                index = index + 1

            for oneAccount in accountList:
                for ele in allAccountList:
                    if oneAccount == ele:
                        addList.append(oneAccount)
                        break
            
            addList = list(set(addList))#去重
            if len(addList) == 0 and noLimit == False:
                ret = get_error_result("ParameterError")
                return ret

            for oneAccount in addList:
                recordObj = tgtdAccount.objects.filter(user=oneAccount)
                passwd = ''
                if len(recordObj) > 0:
                    passwd = recordObj[0].passwd
                else:
                    if noLimit:
                        ret = get_error_result("SetNoUserError")
                    else:
                        ret = get_error_result("SetUserError")
                    return ret

                allLines.insert(len(allLines) - 1, f'\tincominguser {oneAccount} {passwd}\n')

            file = open(configFileName, "w")
            file.writelines(allLines)
            file.close()

            if configFileName.find('.conf') != -1:
                status = os.system(f'tgt-admin --update tid={tid}  -c {configFileName}')
                if status != 0:
                    if noLimit:
                        ret = get_error_result("SetNoUserError")
                    else:
                        ret = get_error_result("SetUserError")
                    return ret

            msg = ''
            # ret['code'] = 0
            if noLimit:
                msg = '设置匿名访问成功'
            else:
                msg = '设置用户访问成功'

            kwargs = {
                'msg' : msg
            }

            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("add account to target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddTargetAccountCmdError")
            return ret

    def dealCmdPeer(self, request):
        try:
            tid = request.data.get('tid')#string
            target = request.data.get('target')#string
            accountList = request.data.get('accountList')#string
            requestEnd = 'backEnd'

            newRequest = {
                'requestEnd':requestEnd,
                'tid' : tid,
                'target' : target,
                'accountList' : accountList,
            }

            return peer_post("/store/iscsiSrv/addTargetAccount/", newRequest)

        except Exception as err:
            logger.error("add account to target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddTargetAccountCmdError")
            return ret    


def delConfigFileTargetAccount(iqn, accountName, confFile):

    result = os.popen('cat -n '+ confFile + ' |sed -n \'/target ' + iqn + '/, /\/target/p\' |grep \'incominguser ' + accountName + '\' |awk \'{print $1}\'', "r")
    lineNumber = result.readlines()
    result.close()
  
    if len(lineNumber) > 0:
        os.system('sed -i \'' + lineNumber[0].split('\n')[0] + 'd\' ' + confFile)


#只删除特定的target里的账户
class iscsiDelTargetAccount(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='iscsi的id'),
            'iqn': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili'),
            'accountName': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='需要删除的账号列表'),
        },
        required=['tid', 'iqn', 'accountName'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("exec cmd string post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.delAccountLocal(request)
                else:
                    ret = self.delAccountPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.delAccountLocal(request)
            else:
                ret = self.delAccountLocal(request)
            
            return JSONResponse(ret)

        except Exception as err:
            logger.error("delete target account error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DelTargetAccountError")
            return JSONResponse(ret)
 
    def delAccountLocal(self, request):
        try:
            ret = {}

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            target = request.data.get('iqn')
            tid = request.data.get('tid')
            accountList = request.data.get('accountName')

            ipStr = getLinkIpStr(target)
            if len(ipStr) != 0:
                kwargs = {
                        'ipStr': ipStr
                    }
                ret = get_error_result("CurTargetHadLink", data=None, **kwargs)
                return ret

            curAccountList = getTargetAccountsStringListByIQN(target)#防止重复删除

            deleteAccount = []
            for oneAccount in curAccountList:
                for account in accountList:
                    if oneAccount.find(account) != -1:#账户已经存在
                        deleteAccount.append(account)
                        break

            deleteAccount = list(set(deleteAccount))#去重
            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("DelTargetAccountError")
                return ret
            
            for account in deleteAccount:
                delConfigFileTargetAccount(target, account, configFileName)
                #result = run_cmd('tgtadm -L iscsi -m account -o unbind -t ' + str(tid) + ' -u ' + account)

            os.system(f'tgt-admin --update tid={tid}  -c {configFileName}')

            
            # ret['code'] = 0
            # ret['msg'] = '删除账户成功'
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("delete target account error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DelTargetAccountError")
            return ret
        
    def delAccountPeer(self, request):
        try:
            iqn = request.data.get('iqn')
            accountName = request.data.get('accountName')
            tid = request.data.get('tid')
            requestEnd = 'backEnd'

            newRequest = {
                'iqn':iqn,
                'accountName':accountName,
                'tid':tid,
                'requestEnd':requestEnd
            }

            #return peer_post("/store/iscsiSrv/iscsiDelTargetAccount/", newRequest)

        except Exception as err:
            logger.error("delete target account error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DelTargetAccountError")
            return ret


class iscsiActive(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'tid': openapi.Schema(type=openapi.TYPE_STRING, description='iscsi的id'),
            'iqn': openapi.Schema(type=openapi.TYPE_STRING, description='target 的名字,像iqn.2023-12.node2.iscsi.com:lili'),
            'activeEnable' :openapi.Schema(type=openapi.TYPE_BOOLEAN, description='激活：true; 不激活：false'),
        },
        required=['tid', 'iqn', 'activeEnable'],
    ))

    def post(self, request, *args, **kwargs):
        try:
            logger.debug("exec cmd string post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.iscsiActiveLocal(request)
                else:
                    ret = self.iscsiActivePeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.iscsiActiveLocal(request)
            else:
                ret = self.iscsiActiveLocal(request)
            
            return JSONResponse(ret)

        except Exception as err:
            logger.error("Active target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("SetTargetActiveError")
            return JSONResponse(ret)
        

    def iscsiActiveLocal(self, request):
        try:
            ret = {}

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            tid =  request.data.get('tid')
            target = request.data.get('iqn')
            activeEnable = request.data.get('activeEnable')

            configFileName = getSpecificTargetConfigFileName(target)
            if len(configFileName) <= 0:
                ret = get_error_result("TargetConfigFileNotExist")
                return ret
            
            if configFileName.find('.invalid') != -1:#前端没有过滤该target是否有效
                ret = get_error_result("TargetInvalid")
                return ret

            if configFileName.find('.conf') != -1 and activeEnable == False:#不激活

                ipStr = getLinkIpStr(target)
                if len(ipStr) != 0:
                    kwargs = {
                            'ipStr': ipStr
                        }
                    ret = get_error_result("CurTargetHadLink", data=None, **kwargs)
                    return ret

                newName = configFileName.replace('.conf', '.inactive')

                result = run_cmd(f'tgtadm -L iscsi -m target -o delete --force -t {tid}')
                if result[0] != 0:
                    # ret['code'] = -1
                    msg = f'id为：{tid} target不存在'
                    kwargs = {
                            'msg': msg
                        }
                    ret = get_error_result("CurTargetNotExist", data=None, **kwargs)
                    return ret
                
                run_cmd(f'mv -f {configFileName} {newName}')

            elif configFileName.find('.inactive') != -1 and activeEnable == True:#激活

                file = open(configFileName, "r")
                allLines = file.readlines()
                file.close()

                secondaryCopyLvmFlag = False
                for line in allLines:
                    if line.find('backing-store') != -1:
                        theLunDev = line.split()[1].split('\n')[0]
                        baseName = os.path.basename(theLunDev)
                        status, outPut = run_cmd(f'drbdadm role {baseName}')
                        if status == 0:#该设备为复制逻辑卷
                            if outPut == 'Secondary':#从端
                                secondaryCopyLvmFlag = True
                                break
                
                newName = ''
                if secondaryCopyLvmFlag:#从端
                    newName = configFileName.replace('.inactive', '.invalid')
                else:
                    newName = configFileName.replace('.inactive', '.conf')
                
                if secondaryCopyLvmFlag == False:
                    newTid = str(getTheMaxTargetId() + 1)
                    result = run_cmd('tgtadm -L iscsi -m target -o new -t ' + newTid + ' -T ' + target)
                    if result[0] != 0:
                        ret = get_error_result("SetTargetActiveError")
                        return ret
                    
                    run_cmd(f'mv -f {configFileName} {newName}')
                
                    run_cmd(f'tgt-admin --update tid={newTid}  -c {newName}')
                
                else:
                    run_cmd(f'mv -f {configFileName} {newName}')
  
            else:
                ret = get_error_result("InvalidOperator")
                return ret

            msg = ''
            # ret['code'] = 0
            if activeEnable == False:
                msg = 'target 失活成功'
            else :
                msg = 'target 激活成功'
 
            kwargs = {
                    'msg': msg
                }
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("Active target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("SetTargetActiveError")
            return ret
 

    def iscsiActivePeer(self, request):
        try:
            tid =  request.data.get('tid')
            target = request.data.get('iqn')
            activeEnable = request.data.get('activeEnable')
            requestEnd = 'backEnd'

            newRequest = {
                'tid':tid,
                'iqn':target,
                'activeEnable':activeEnable,
                'requestEnd':requestEnd
            }

            return peer_post("/store/iscsiSrv/iscsiActive/", newRequest)
         
        except Exception as err:
            logger.error("Active target error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("SetTargetActiveError")
            return ret

class getAllAccountList(APIView):

    @swagger_auto_schema(None)

    def post(self, request, *args, **kwargs):
        try:
            ret = {}

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return JSONResponse(ret)

            allAccountList = getAllAcountsList()

            # ret['code'] = 0
            # ret['msg'] = '获取iscsi所有账户成功'
            # ret['data'] = allAccountList
            ret = get_error_result("Success", data=allAccountList)
            return JSONResponse(ret)

        except Exception as err:
            logger.error("delete target account error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetIscsiAllAccountError")
            JSONResponse(ret)


class addAccountToIscsi(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'userName': openapi.Schema(type=openapi.TYPE_STRING, description='用户的名称'),
            'passwd': openapi.Schema(type=openapi.TYPE_STRING, description='用户的密码'),
        },
        required=['userName', 'passwd'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug("exec cmd string post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.addAccountToIscsiLocal(request)
                else:
                    ret = self.addAccountToIscsiPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.addAccountToIscsiLocal(request)
            else:
                ret = self.addAccountToIscsiLocal(request)
            
            return JSONResponse(ret)

        except Exception as err:
            logger.error("add account To iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddAccountToIscsiError")
            return JSONResponse(ret)


    def addAccountToIscsiLocal(self, request):

        try:
            ret = {}

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            userName =  request.data.get('userName')
            passwd = request.data.get('passwd')

            allAccountList = getAllAcountsList()

            for oneAccount in allAccountList:

                if oneAccount == userName:

                    ret = get_error_result("AccountHadExist")
                    return ret
                
            status, exeString = run_cmd(f'tgtadm -L iscsi -m account -o new -u {userName} -p {passwd}')
            if status != 0:
                ret = get_error_result("AddAccountToIscsiError")
                return ret
            
            record = {
                'user':userName,
                'passwd' : passwd
            }
            tgtdAccount.objects.create(**record)

            # ret['code'] = 0
            # ret['msg'] = '添加账户到ISCSI成功'
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("add account To iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddAccountToIscsiError")
            return ret
        
    def addAccountToIscsiPeer(self, request):
        try:
            userName =  request.data.get('userName')
            passwd = request.data.get('passwd')
            requestEnd = 'backEnd'

            newRequest = {
                'userName':userName,
                'passwd':passwd,
                'requestEnd':requestEnd
            }

            return peer_post("/store/iscsiSrv/addAccountToIscsi/", newRequest)
         
        except Exception as err:
            logger.error("add account To iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("AddAccountToIscsiError")
            return ret


class deleteAccountFromIscsi(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'accountList': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING), description='账户列表' ),
        },
        required=['accountList'],
    ))

    def post(self, request, *args, **kwargs):

        try:
            logger.debug("exec cmd string post request")
            logger.debug(request.data)

            ret = {}

            requestEnd = request.data.get('requestEnd')

            #判断是否为前端发起请求，前端请求需要处理双机流程
            if requestEnd == "frontend":
                #处理脱机运行正常返回数据
                peerInfo = ClusterNode.objects.values("ip", "host_name", "status").first()
                if not peerInfo:
                    peerInfo = {"ip": "", "host_name": "", "status": -1}
                
                peerStatus = peerInfo["status"]

                #对端机器不正常，只运行单机创建
                if peerStatus == -1 :
                    ret = self.deleteAccountFromIscsiLocal(request)
                else:
                    ret = self.deleteAccountFromIscsiPeer(request)
                    if ret.get('code') != 0:
                        return JSONResponse(ret)
                    ret = self.deleteAccountFromIscsiLocal(request)
            else:
                ret = self.deleteAccountFromIscsiLocal(request)
            
            return JSONResponse(ret)

        except Exception as err:
            logger.error("delete account from iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DelAccountToIscsiError")
            return JSONResponse(ret)


    def deleteAccountFromIscsiLocal(self, request):
        try:
            ret = {}

            if checkTgtdServerOnline() == False:

                ret = get_error_result("IscsiServerNotOnline")
                return ret

            accountList =  request.data.get('accountList')

            allConfigNameList = getAllTargetConfigFileNameList()
            for configName in allConfigNameList:

                iqn = ''
 
                if configName.find('.conf') != -1:
                    iqn = configName.split('.conf')[0].split('/')[4]
                    
                elif configName.find('.invalid') != -1:
                    iqn = configName.split('.invalid')[0].split('/')[4]

                elif configName.find('.inactive') != -1:
                    iqn = configName.split('.inactive')[0].split('/')[4]

                else:
                    logger.debug('------>无效配置文件:' + configName)
                    continue

                theTargetAccountList = getTargetAccountsStringListByIQN(iqn)
                logger.debug(f"{iqn}账户:{theTargetAccountList}")

                for ele in theTargetAccountList:

                    for name in accountList:
                        if ele == name:
                            kwargs = {
                                'detail': f'账户：{name}正在被target:{iqn}占用'
                            }
                            ret = get_error_result("GloableAccountHadUserdError", data=None, **kwargs)
                            return ret
                            

            for account in accountList:
                logger.debug(f'删除账户：{account}')
                os.system(f'tgtadm -L iscsi -m account -o delete -u {account}')
                recordObj = tgtdAccount.objects.filter(user=account)
                recordObj.delete()


            # ret['code'] = 0
            # ret['msg'] = '删除ISCSI账户成功'
            ret = get_error_result("Success")
            return ret

        except Exception as err:
            logger.error("delete account from iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DelAccountToIscsiError")
            return ret


    def deleteAccountFromIscsiPeer(self, request):
        try:
            accountList =  request.data.get('accountList')
            requestEnd = 'backEnd'

            newRequest = {
                'accountList':accountList,
                'requestEnd':requestEnd
            }

            return peer_post("/store/iscsiSrv/deleteAccountFromIscsi/", newRequest)
         
        except Exception as err:
            logger.error("delete account from iscsi error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DelAccountToIscsiError")
            return ret