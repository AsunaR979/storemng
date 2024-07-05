import datetime
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
import pytz

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
from web_manage.hardware.models import AutoSnapTask
from storesys.settings import TIME_ZONE, scheduler

logger = logging.getLogger(__name__)


class AutoSnapCmd(Enum):
    AddJob = "addJob"
    RemoveJob = "removeJob"
    PauseJob = "pauseJob"
    ResumeJob = "resumeJob"
    ModifyJob = "modifyJob"
    GetOneJobDetail = "getOneJobDetail"


class AutoSnapView(APIView):
    '''
    快照    lvcreate --snapshot  -L 20m  --name snap1 /dev/vg1/lvname1
    '''
    def get(self, request, *args, **kwargs):
        try:
            # 获取逻辑卷信息 lvpath: lvsize ,key-value形式的数据
            command_lvs = "lvs --noheadings --separator=',' -o lv_name,vg_name,lv_attr,lv_size,lv_path,origin,lv_time"
            output_lvs = subprocess.check_output(command_lvs, shell=True, encoding='utf-8')
            lines = output_lvs.strip().splitlines()
            allLvSizeInfo = {}
            for line in lines:
                fields = [item.strip() for item in line.split(",")] # 去除元素中的首尾空格
                allLvSizeInfo[fields[4]] = fields[3]
            # 获取所有任务列表
            jobs = scheduler.get_jobs()
            jobIds = [ele.id for ele in jobs]
            # 获取所有 AutoSnapTask 记录
            auto_snap_tasks = AutoSnapTask.objects.all()
            # sqlite3 UTC 转为django配置的时区时间
            # 获取设置时区
            target_tz = pytz.timezone(TIME_ZONE)

            # 组织表的详细信息为字典对象的数组
            table_details = []
            for task in auto_snap_tasks:
                # 将解析后的 datetime 对象转换为目标时区
                stdtime = task.stdtime.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")
                endtime = task.endtime.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")

                # 默认状态：表示未开始
                tskstatus = 0
                # 当前时间大于任务结束时间，状态直接置为“已结束”
                if datetime.datetime.now().astimezone(target_tz) > task.endtime.astimezone(target_tz):
                    tskstatus = 2
                else:
                    if task.tsknm in jobIds:
                        job = scheduler.get_job(task.tsknm)
                        if job:
                            if job.next_run_time is None:
                                tskstatus = 0
                            # 正在运行中
                            elif job.next_run_time < job.trigger.end_date:
                                tskstatus = 1
                            # 已经结束运行
                            else:
                                tskstatus = 2
                # 获取逻辑卷当前的大小
                lvpath = "/dev/" + task.vgname + "/" + task.lvname
                task_details = {
                    'id': task.id,
                    'tsknm': task.tsknm,
                    'lvname': task.lvname,
                    'vgname': task.vgname,
                    'size': task.size,
                    'lvsize': allLvSizeInfo[lvpath],
                    'interval': task.interval,
                    'period': task.period,
                    'stdtime': stdtime,
                    'endtime': endtime,
                    'svnum': task.svnum,
                    'is_loop_write': (bool)(task.is_loop_write), 
                    'updated_at': task.updated_at.strftime("%Y-%m-%d %H:%M:%S") if task.updated_at else None,
                    'created_at': task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'status': tskstatus                
                }
                table_details.append(task_details)
            # 以JSON格式返回逻辑卷信息列表
            return JSONResponse(table_details)
        except Exception as e:
            logger.error("get auto snap task error: %s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'command': openapi.Schema(type=openapi.TYPE_STRING, enum=[v for v in AutoSnapCmd.__members__.values()]),
            'taskName': openapi.Schema(type=openapi.TYPE_STRING),
            'lvpath': openapi.Schema(type=openapi.TYPE_STRING),
            'size': openapi.Schema(type=openapi.TYPE_STRING),
            'interval': openapi.Schema(type=openapi.TYPE_INTEGER),
            'period': openapi.Schema(type=openapi.TYPE_STRING),
            'startDate': openapi.Schema(type=openapi.TYPE_STRING),
            'is_loop_write': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            'endDate': openapi.Schema(type=openapi.TYPE_STRING),
            'snapNumber': openapi.Schema(type=openapi.TYPE_INTEGER),
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
            if command == "addJob":
                ret = self.add_autosnap_job(request, args, kwargs)
            elif command == "removeJob":
                ret = self.remove_autosnap_job(request, args, kwargs)
            elif command == "pauseJob":
                ret = self.pause_autosnap_job(request, args, kwargs)         
            elif command == "resumeJob":
                ret = self.resume_autosnap_job(request, args, kwargs)
            elif command == "modifyJob":
                ret = self.modify_autosnap_job(request, args, kwargs)
            elif command == "getOneJobDetail":
                ret = self.get_one_job_detail(request, args, kwargs)
            else:
                ret = get_error_result("MessageError")
            return JSONResponse(ret)
        except Exception as e:
            logger.error("user execute %s error: " % command)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    # 根据快照个数，获取下一个快照编号
    def get_next_snap_name(self, taskName, lvPath, snapNumber):
        try:
            vg_name = lvPath.split('/')[2]
            lv_name = lvPath.split('/')[3]
            # 获取逻辑卷信息
            command_lvs = "lvs --noheadings --separator=',' -o lv_name,vg_name,lv_attr,lv_size,lv_path,origin,lv_time"
            output_lvs = subprocess.check_output(command_lvs, shell=True, encoding='utf-8')

            # 解析输出结果
            lines = output_lvs.strip().splitlines()
            # 构建所有该任务生成的快照信息列表
            autosnap_volumes = []
            for line in lines:
                fields = [item.strip() for item in line.split(",")] # 去除元素中的首尾空格
                snap_name = fields[0]
                origin = "" if len(fields) < 6 else fields[5]
                create_time = " ".join(fields[6].split()[:2]) if len(fields) > 5 else ""
                # lv_path = fields[4] fields[5] == origin 
                if lv_name != origin:
                    continue
                if snap_name.startswith("auto_" + taskName + "_"):
                    autosnap_volumes.append({
                        'name': snap_name,
                        'ctime': create_time
                    })
            # 按照创建快照时间倒序排列，取第一个元素的name，根据此元素最后的编号，重组下一个快照名
            autosnap_volumes.sort(key=lambda x:x['ctime'], reverse=True)
            if not autosnap_volumes:
                nextSnapName = "auto_" + taskName + "_1"
                nextSnapNum = 1
            else:
                prevSnapNum = int(autosnap_volumes[0]['name'].split('_')[2])
                nextSnapNum = 1 if prevSnapNum == int(snapNumber) else prevSnapNum + 1
                nextSnapName = "auto_" + taskName + "_" + str(nextSnapNum)
            if nextSnapName in [ele['name'] for ele in autosnap_volumes]:
                snap_path = "/dev/" + vg_name + "/" + nextSnapName
                # 删除已经存在的快照
                cmd = 'lvremove -f {}'.format(snap_path)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    if 'contains a filesystem in use' in output:
                        logger.error("Please unmount the snap volume first!!!")
                        resp = get_error_result("UmountLvFirst")
                    elif 'is used by another device' in output:
                        logger.error("The snap volume is currently being used by another device, so it cannot be manipulated!!!")
                        resp = get_error_result("LvIsUsedByOther")
                    else:
                        logger.error("Failed to delete snap volume!!!")
                        resp = get_error_result("DeleteLvError")
            # 返回下一个快照名称，已有的快照总数
            return (nextSnapName, len(autosnap_volumes))
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    def create_snap(self, taskInfo):
        try:
            taskName = taskInfo['taskName']
            lvpath = taskInfo['lvpath']
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = taskInfo['size']
            snapNumber = taskInfo['snapNumber']
            is_loop_write = taskInfo['is_loop_write']
            (snap_lv_name, generatedSnapSum) = self.get_next_snap_name(taskName, lvpath, snapNumber)
            # 设置为非循环写，并且已有快照次数达到最大次数-1，直接停止定时任务，但是本次最后一次继续执行完
            if not is_loop_write and generatedSnapSum == int(snapNumber)-1:
                scheduler.remove_job(job_id=taskName, jobstore=None)

            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            if snap_lv_name:
                cmd = 'lvcreate -s -n {} -L {} {}'.format(snap_lv_name, size, lvpath)
                (status, output) = run_cmd(cmd)
                if status != 0:
                    logger.error("Failed to create snapshot!!!")
            else:
                logger.error('request data invalid!!!')
            logger.info(f'create_snap taskName: {taskName}, lvpath: {lvpath}, snapLv: {snap_lv_name}')
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
        
    # 创建任务
    def add_autosnap_job(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            taskName = request.data.get('taskName')
            lvpath = request.data.get('lvpath')
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = request.data.get('size')
            interval = int(request.data.get('interval'))
            period = request.data.get('period')
            startDate = request.data.get('startDate')
            endDate = request.data.get('endDate')
            snapNumber = int(request.data.get('snapNumber'))
            is_loop_write = request.data.get('is_loop_write')

            # 数据校验
            if taskName:
                # 1、判断任务名称是否重复
                autoSnapTasks = AutoSnapTask.objects.all()
                allTaskNames = [element.tsknm for element in autoSnapTasks]
                if taskName in allTaskNames:
                    resp = get_error_result("AutoSnapTaskNameAlreadyExists")
                    return resp

                # 2、判断用户设置的开始结束时间是否够执行至少一次任务
                # 将解析后的 datetime 对象转换为目标时区
                stdtime = datetime.datetime.strptime(startDate, "%Y-%m-%d %H:%M:%S")
                endtime = datetime.datetime.strptime(endDate, "%Y-%m-%d %H:%M:%S")
                # 计算时间差
                timeDiff = endtime - stdtime
                if stdtime < datetime.datetime.now():
                    timeDiff = endtime - datetime.datetime.now()

                taskInfo = {
                    "taskName": taskName,
                    "lvpath": lvpath,
                    "size": size,
                    "snapNumber": snapNumber,
                    "is_loop_write": is_loop_write
                }
                if period == "weeks":
                    intervalDiff = datetime.timedelta(weeks=interval)
                    # 计算给定最小间隔执行任务的周期时间差，判断是否时间段足够执行一次任务
                    if timeDiff < intervalDiff:
                        resp = get_error_result("InvalidAutoSnapTaskError")
                        return resp
                    scheduler.add_job(self.create_snap, 'interval', id=taskName, weeks=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                elif period == "days":
                    intervalDiff = datetime.timedelta(days=interval);
                    if timeDiff < intervalDiff:
                        resp = get_error_result("InvalidAutoSnapTaskError")
                        return resp
                    scheduler.add_job(self.create_snap, 'interval', id=taskName, days=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                elif period == "hours":
                    intervalDiff = datetime.timedelta(hours=interval);
                    if timeDiff < intervalDiff:
                        resp = get_error_result("InvalidAutoSnapTaskError")
                        return resp
                    scheduler.add_job(self.create_snap, 'interval', id=taskName, hours=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                elif period == "minutes":
                    intervalDiff = datetime.timedelta(minutes=interval);
                    if timeDiff < intervalDiff:
                        resp = get_error_result("InvalidAutoSnapTaskError")
                        return resp
                    scheduler.add_job(self.create_snap, 'interval', id=taskName, minutes=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                else:
                    resp = get_error_result("MessageError")
                    return resp
                # 解析字符串日期时间
                stdtime = datetime.datetime.strptime(startDate, '%Y-%m-%d %H:%M:%S')
                endtime = datetime.datetime.strptime(endDate, '%Y-%m-%d %H:%M:%S')
                
                # 获取本地时区
                local_tz = pytz.timezone(TIME_ZONE)  # 请根据您的本地时区调整
                
                # 将解析后的 datetime 对象转换为本地时区
                stdtime = local_tz.localize(stdtime)
                endtime = local_tz.localize(endtime)

                # 数据库记录存储类型
                values = {
                    "tsknm": taskName,
                    "lvname": lvpath.split('/')[3],
                    "vgname": lvpath.split('/')[2],
                    "size": size,
                    "interval": interval,
                    "period": period,
                    "stdtime": stdtime,
                    "endtime": endtime,
                    "svnum": snapNumber,
                    "is_loop_write": 1 if is_loop_write else 0,
                }
                # 数据插入数据库保存
                AutoSnapTask.objects.create(**values)
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("CreateAutoSnapTaskError")
            return resp

    # 移除任务
    def remove_autosnap_job(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            taskName = request.data.get('taskName')
            sqlId = request.data.get('id')

            # 数据校验
            if taskName:
                # 先判断此任务状态，如果是未开始，则不对scheduler操作
                jobs = scheduler.get_jobs()
                jobIds = [ele.id for ele in jobs]
                if taskName in jobIds:
                    # 判断该任务状态，如果是运行中，禁止删除（防止正在运行的任务强行结束）
                    job = scheduler.get_job(taskName)
                    if job and job.next_run_time and job.next_run_time < job.trigger.end_date:
                        resp = get_error_result("RemoveRunningAutoSnapError")
                        return resp
                    scheduler.remove_job(job_id=taskName, jobstore=None)
                # 删除数据库记录
                AutoSnapTask.objects.filter(id=sqlId, tsknm=taskName).delete()
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("RemoveAutoSnapTaskError")
            return resp

    # 暂停任务
    def pause_autosnap_job(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            taskName = request.data.get('taskName')
            sqlId = request.data.get('id')
            # 数据校验
            if taskName:
                # 先判断此任务状态，如果是未开始，则不对scheduler操作
                jobs = scheduler.get_jobs()
                jobIds = [ele.id for ele in jobs]
                if taskName in jobIds:                
                    scheduler.pause_job(job_id=taskName, jobstore=None)
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("PauseAutoSnapTaskError")
            return resp

    # 恢复任务
    def resume_autosnap_job(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            taskName = request.data.get('taskName')
            sqlId = request.data.get('id')
            # 查询数据库获取其他信息
            task = AutoSnapTask.objects.get(id=sqlId)
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            lvpath = "/dev/" + task.vgname + "/" + task.lvname
            size = task.size
            interval = int(task.interval)
            period = task.period
            startDate = task.stdtime.strftime("%Y-%m-%d %H:%M:%S")
            endDate = task.endtime.strftime("%Y-%m-%d %H:%M:%S")
            snapNumber = task.svnum
            is_loop_write = True if task.is_loop_write else False

            # 数据校验
            if taskName:
                # 先判断此任务状态，如果是未开始，则不对scheduler操作
                jobs = scheduler.get_jobs()
                jobIds = [ele.id for ele in jobs]
                if taskName in jobIds:                
                    scheduler.resume_job(job_id=taskName, jobstore=None)
                else:
                    taskInfo = {
                        "taskName": taskName,
                        "lvpath": lvpath,
                        "size": size,
                        "snapNumber": snapNumber,
                        "is_loop_write": is_loop_write
                    }
                    if period == "weeks":
                        scheduler.add_job(self.create_snap, 'interval', id=taskName, weeks=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                    elif period == "days":
                        scheduler.add_job(self.create_snap, 'interval', id=taskName, days=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                    elif period == "hours":
                        scheduler.add_job(self.create_snap, 'interval', id=taskName, hours=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                    elif period == "minutes":
                        scheduler.add_job(self.create_snap, 'interval', id=taskName, minutes=interval, start_date=startDate, end_date=endDate, args=[taskInfo], coalesce=True, max_instances=1)
                    else:
                        resp = get_error_result("MessageError")
                        return resp

                # 是否记录状态到数据库
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("ResumeAutoSnapTaskError")
            return resp

    # 修改任务
    def modify_autosnap_job(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            sqlId = request.data.get('id')
            taskName = request.data.get('taskName')
            lvpath = request.data.get('lvpath')
            # size 这里需要验证，前端可以进行限制数字输入，然后带单位
            size = request.data.get('size')
            interval = int(request.data.get('interval'))
            period = request.data.get('period')
            startDate = request.data.get('startDate')
            endDate = request.data.get('endDate')
            snapNumber = int(request.data.get('snapNumber'))
            is_loop_write = request.data.get('is_loop_write')

            # 数据校验
            if taskName:
                # 解析字符串日期时间
                stdtime = datetime.datetime.strptime(startDate, '%Y-%m-%d %H:%M:%S')
                endtime = datetime.datetime.strptime(endDate, '%Y-%m-%d %H:%M:%S')
                
                # 获取本地时区
                local_tz = pytz.timezone(TIME_ZONE)  # 请根据您的本地时区调整
                
                # 将解析后的 datetime 对象转换为本地时区
                stdtime = local_tz.localize(stdtime)
                endtime = local_tz.localize(endtime)

                # 数据库记录存储类型
                is_loop_write = 1 if is_loop_write else 0
                # 数据更新到数据库保存
                AutoSnapTask.objects.filter(id=sqlId, tsknm=taskName).update(
                    size=size, interval=interval, period=period,
                    stdtime=stdtime, endtime=endtime, svnum=snapNumber, is_loop_write=is_loop_write)                
            else:
                resp = get_error_result("MessageError")
            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("ModifySnapTaskError")
            return resp

    # 获取单个任务详情
    def get_one_job_detail(self, request, args, kwargs):
        try:
            resp = get_error_result("Success")
            sqlId = request.data.get('id')
            taskName = request.data.get('taskName')

            # 获取所有任务列表
            jobs = scheduler.get_jobs()
            jobIds = [ele.id for ele in jobs]
            # 获取所有 AutoSnapTask 记录
            task = AutoSnapTask.objects.filter(id=sqlId, tsknm=taskName).first()

            # 组织表的详细信息为字典对象
            table_detail = {}
            # 默认状态：表示不存在
            tskstatus = 0
            if task.tsknm in jobIds:
                job = scheduler.get_job(task.tsknm)
                if job:
                    # 正在运行中
                    if job.next_run_time is None:
                        tskstatus = 1
                    # 已经结束运行
                    elif job.next_run_time > job.trigger.end_date:
                        tskstatus = 2
                    # 还未开始
                    else:
                        tskstatus = 0
            task_details = {
                'id': task.id,
                'tsknm': task.tsknm,
                'lvname': task.lvname,
                'vgname': task.vgname,
                'size': task.size,
                'interval': task.interval,
                'period': task.period,
                'stdtime': task.stdtime.strftime("%Y-%m-%d %H:%M:%S"),
                'endtime': task.endtime.strftime("%Y-%m-%d %H:%M:%S") if task.endtime else None,
                'svnum': task.svnum,
                'is_loop_write': 1 if task.is_loop_write else 0,
                'updated_at': task.updated_at.strftime("%Y-%m-%d %H:%M:%S") if task.updated_at else None,
                'created_at': task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                'status': tskstatus
            }
            # 以JSON格式返回逻辑卷信息列表
            return JSONResponse(table_detail)
        except Exception as e:
            logger.error("get auto snap job detail error: %s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)
