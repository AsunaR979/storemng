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
import threading
import pytz

from rest_framework.decorators import action
from web_manage.cluster.drbd.models import CopyLvAsyncTask
from web_manage.common import constants
from web_manage.common.http import peer_post
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



class CopyLvAsyncUpdate():
    '''
    DRBD的异步模式：使用异步策略进行同步数据，平时就是脱机使用
    '''
    def exec_async_update_data(self, resName, taskInfo):
        logger.info(f"{resName} async update starting...")
        # 1、drbd盘的必须为主角色，不为主角色，则本节点任务不执行，（只有是可以在用的drbd盘才会执行数据同步）先读取对应配置文件信息
        (status, roleName) = run_cmd("drbdadm role %s" % resName)
        if status != 0 or roleName.lower() != "primary":
            logger.error(f"CopyLvAsyncUpdate: {resName} exception, get role status: {status}, role: {roleName}")
            return

        # 2、本地启用连接对端
        (status, connectCmdOutput) = run_cmd("drbdadm connect %s" % (resName))
        if status != 0:
            logger.error(f"CopyLvAsyncUpdate: connect {resName} exception, output: {connectCmdOutput}")
            return
        
        # 3、对端启用从角色，启用连接,需要发起http请求api
        data = {
                "command": "startLvCopy",
                "requestEnd": "backend",
                "role": "secondary",
                "lvName": resName
            }
        startPeerResp = peer_post("/cluster/doubleCtlStore/lvCopy", data)
        if startPeerResp.get('code') != 0:
            logger.error(f"start peer secondary failed, resp data: {startPeerResp.get('msg')}")
            return

        # 4、如果有超时设置，则开启超时，超时处理就是断开drbd盘的连接
        if taskInfo['timeoutHours']:
            timer = threading.Timer(int(taskInfo['timeoutHours'])*60, lambda: self.stopUpdateData(resName))
            timer.start()

        # 5、死循环等待数据同步完成，完成则退出并且把本地的连接断开即可
        while True:
            # 检测drbd盘的磁盘更新状态
            (status, dstate) = run_cmd("drbdadm dstate %s" % resName)
            if status != 0:
                logger.error(f"get {resName} dstate failed")
                return
            # 更新成功，则退出循环
            if dstate == "UpToDate/UpToDate":
                logger.info(f"{resName} async update success.")
                # 把drbd盘的连接再次断开
                (status, output) = run_cmd("drbdadm disconnect %s" % (resName))
                if status != 0:
                    logger.error(f"exec_async_update_data: back to disconnect {resName} exception, output: {output}")
                # 完成更新任务，退出死循环
                break
            # 休眠，等待磁盘更新
            time.sleep(2)
            # 判断drbd的连接状态，如果是断开了，说明环境异常或者是超时处理断开的
            (status, cstate) = run_cmd("drbdadm cstate %s" % resName)
            if status != 0 or cstate.lower() != "connected":
                logger.error(f"get {resName} cstate expction, status: {status}, cstate: {cstate}")
                return
        # 5、打印更新结束时间
        logger.info(f"{resName} async update end.")

    def stopUpdateData(self, resName):
        '''
        断开drbd盘的连接，进入脱机运行
        '''
        (status, output) = run_cmd("drbdadm disconnect %s" % (resName))
        if status != 0:
            logger.error(f"CopyLvAsyncUpdate: disconnect {resName} exception, output: {output}")
            return
        logger.warn(f"{resName} async update timeout.")
        
    def add_async_update_data_job(self, resName, taskInfo):
        '''
        添加drbd异步更新定时任务
        输入参数都是字符串格式，除了day_of_week是字符串，使用逗号分割 [0, 6]， 0到6（0 代表周一）
        taskInfo = {
            period: "week", # month, week, day 
            day: "",  # 1-31
            day_of_week: "0,6",  # 0-6
            hour: "8",  # 0-23
            minute: "30", # 0-59
            timeoutHours: "3" # 1->
        }
        '''
        try:
            # 由于已有自动快照等其他定时任务，防止任务名称重复，额外添加特殊前缀
            taskName = "copyLvAsync_" + resName
            # 1、判断任务名称是否重复
            copyLvAsyncTasks = CopyLvAsyncTask.objects.all()
            allResNames = [element.resname for element in copyLvAsyncTasks]
            if resName in allResNames:
                logger.error(f"{resName} copy lv async task already exists in db.")
                return

            if taskInfo["period"] == "month":
                # 每月指定时间执行
                scheduler.add_job(self.exec_async_update_data, 'cron', id=taskName, day=taskInfo["day"], hour=taskInfo["hour"], minute=taskInfo["minute"], args=[resName, taskInfo], coalesce=True, max_instances=1) 
            elif taskInfo["period"] == "week":
                # 每周指定时间执行，注意：day_of_week 的值可以是 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun' 或者它们的缩写 '0' 到 '6'（0 代表周一）
                scheduler.add_job(self.exec_async_update_data, 'cron', id=taskName, day_of_week=taskInfo["day_of_week"], hour=taskInfo["hour"], minute=taskInfo["minute"], args=[resName, taskInfo], coalesce=True, max_instances=1)
            elif taskInfo["period"] == "day":
                # 每日指定时间执行，你可以省略 day 或 day_of_week，因为它们是可选的，并且默认是 '*'（表示每一天）  
                scheduler.add_job(self.exec_async_update_data, 'cron', id=taskName, hour=taskInfo["hour"], minute=taskInfo["minute"], args=[resName, taskInfo], coalesce=True, max_instances=1)

            # 数据库记录存储类型
            values = {
                "resname": resName,
                "period": taskInfo["period"],
                "hour": taskInfo["hour"],
                "minute": taskInfo["minute"],
                "day": taskInfo["day"],
                "day_of_week": taskInfo["day_of_week"],
                "timeout_hours": taskInfo["timeoutHours"],
            }
            # 数据插入数据库保存
            CopyLvAsyncTask.objects.create(**values)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))

    # 移除任务
    def remove_async_update_data_job(self, resName):
        try:
            taskName = "copyLvAsync_" + resName
            # 先判断此任务状态，如果是未开始，则不对scheduler操作
            jobs = scheduler.get_jobs()
            jobIds = [ele.id for ele in jobs]
            if taskName in jobIds:
                # 判断该任务状态，如果是运行中，禁止删除（防止正在运行的任务强行结束）
                job = scheduler.get_job(taskName)
                if job:
                    scheduler.remove_job(job_id=taskName, jobstore=None)
            # 删除数据库记录
            CopyLvAsyncTask.objects.filter(resname=resName).delete()
        except Exception as err:
            logger.error(f"remove_async_update_data_job  error: {err}")
            logger.error(''.join(traceback.format_exc()))

    # 修改任务
    def modify_async_update_data_job(self, resName, taskInfo):
        try:
            # 删除任务
            self.remove_async_update_data_job(resName)
            # 重建任务
            self.add_async_update_data_job(taskInfo)
        except Exception as err:
            logger.error(f"modify_async_update_data_job  error: {err}")
            logger.error(''.join(traceback.format_exc()))

    # 获取单个任务详情
    def get_one_job_detail(self, resName):
        try:
            # 获取所有 AutoSnapTask 记录
            task = CopyLvAsyncTask.objects.filter(resName=resName).first()

            # 组织表的详细信息为字典对象
            task_details = {
                'id': task.id,
                'resname': task.resname,
                'period': task.period,
                'hour': task.hour,
                'minute': task.minute,
                'day': task.day,
                'day_of_week': task.day_of_week,
                'timeout_hours': task.timeout_hours,
                'updated_at': task.updated_at.strftime("%Y-%m-%d %H:%M:%S") if task.updated_at else None,
                'created_at': task.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            return task_details
        except Exception as err:
            logger.error(f"get_one_job_detail CopyLvAsyncTask  error: {err}")
            logger.error(''.join(traceback.format_exc()))
