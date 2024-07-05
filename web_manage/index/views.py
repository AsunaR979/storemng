from collections import defaultdict
import datetime
import os
import platform
import re
import subprocess
import time
import traceback
import logging
from django.http import Http404, HttpResponseServerError
from rest_framework.views import APIView
from storesys.perfData import get_lv_disk_mapped
from web_manage.common.cmdutils import run_cmd
from web_manage.common.constants import SYS_DEVICE_PATH
from web_manage.common.utils import JSONResponse, TimeType, WebPagination, get_error_result, translateUTCOrLoaclTimeStringToLocalTime
from web_manage.admin.models import OperationLog
from web_manage.admin.serializers import OperationLogSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import psutil
import socket
from storesys.settings import VERSION
import pytz

from web_manage.index.models import SystemInfo
from web_manage.perfdata.models import SysMonitoy


logger = logging.getLogger(__name__)


class SystemHardDiskinfoData(APIView):
    """
    get HardDiskinfo
    """
    def get(self,request,*args,**kwargs):
        try:
            resp =get_error_result("Success")
            cmd = 'lsblk -d -o name,tran,size'
            (status, data) = run_cmd(cmd)
            diskdata = data.split('\n')


            disk_info = {}
            json_arr = []

            for items in diskdata[1:]:
                item =  items.split()
                if len(item) < 3:
                    continue
                name = item[0]
                tran = item[1]
                size = item[2]
                if tran in disk_info:
                    disk_info[tran].append((name,size))
                else:
                    disk_info[tran] = [(name,size)]

            for type,info in disk_info.items():
                size = 0
                useds = 0
                notUseds = 0
                for item in info:
                    disk_path = "/dev/" + item[0]
                    used = self.is_disk_mounted(disk_path)
                    if used:
                        useds = useds +1
                    else:
                        notUseds += 1 
                    data = self.convert_to_bytes(item[1])
                    size = size + data
                # gb = size / (1024 ** 3)
                disk_info_data = {'type':type,'quantity':len(info),'size':size,'Already_used':useds,'Not_used':notUseds}

                json_arr.append(disk_info_data)
                   
            resp['data'] = json_arr
            return JSONResponse(resp)
        except Exception as err:
            logger.error("Get system monitor top data error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("OtherError")
            return JSONResponse(resp)
        
    def convert_to_bytes(self,size_str):
        #转换计算
        multipliers = {'K':1024,'M':1024**2,'G':1024**3,'T':1024**4}
        size_str = size_str.upper()
        for suffix in multipliers:
            if size_str.endswith(suffix):
                num = float(size_str[:-1 * len(suffix)])
                return int(num * multipliers[suffix])
        return int(size_str)
    
    def is_disk_mounted(self,disk_name):  
        """
        Check if a disk and all its partitions are mounted.
        """  
        try:  
            # 使用lsblk命令列出磁盘及其分区信息  
            output = subprocess.check_output(['lsblk', '-o', 'NAME,MOUNTPOINT', disk_name], text=True)  
            lines = output.strip().split('\n')  
    
            # 遍历每一行输出结果，检查是否有挂载点  
            for line in lines:  
                if not line:  
                    continue  # 忽略空行  
                match = re.match(r'^(?P<name>.+)\s+(?P<mountpoint>.+)$', line)  
                if match: 
                    name = match.group('name')  
                    mountpoint = match.group('mountpoint')  
                    mountpoint = mountpoint.replace(" ", "")
                    if not mountpoint or mountpoint == '' or mountpoint == 'MOUNTPOINT':  
                        continue
                    else:
                        return True 
    
            # 如果所有分区都有挂载点，则返回True  
            return False  
    
        except subprocess.CalledProcessError:  
            # 如果命令执行失败，则返回False  
            return False 
    

        
            


class SystemMonitorTopData(APIView):
    """
    get top data: cpu memory disk network
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'statis_period': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['username', 'password'],
    ))
    def post(self, request, *args, **kwargs):
        try:
            logger.debug("system monitor post request")
            statis_period = request.data.get("statis_period")
            req_data = {
                "statis_period": int(statis_period)
            }

            hostname = socket.gethostname()
            disk_util = self.get_disk_util()
            #cpu
            cpu_info =  self.get_cpu_info()
            #磁盘io
            diskio_info , sing_disk,network_info,sing_network = self.get_diskio_info()
            # network_info  , sing_network = self.get_network_info()
            #内存
            mem_info = self.get_men_info()
            
            systeminfo = self.get_system_info()

            boot_time = psutil.boot_time()
            boot_time_dt = datetime.datetime.fromtimestamp(boot_time)
            boot_time_str = boot_time_dt.strftime("%Y-%m-%d %H:%M:%S")
            now = datetime.datetime.now()
            uptime = now - boot_time_dt
            # temperatures = psutil.sensors_temperatures()['coretemp'][0].current
            ret = {
                "cpu_util": [ cpu_info],
                "disk_util": [ [hostname, disk_util[0], disk_util[1], disk_util[2]] ],
                "memory_util": [ mem_info],
                "diskio_info": [diskio_info],
                "network_info": [network_info],
                "sing_network": [sing_network],
                "sing_disk": [sing_disk],
                'boot_time_str':[boot_time_str],
                'uptime':[uptime],
                'systeminfo':[systeminfo]
            }
            return JSONResponse(ret)
        except Exception as err:
            logger.error("Get system monitor top data error: %s", err)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("OtherError")
            return JSONResponse(ret)

    def get_disk_list(self):
        (status, cmd_ret) = run_cmd('lsblk -d --output NAME,TYPE|awk \'$2 == "disk"{print $1}\'')
        cmd_ret = cmd_ret.split('\n')
        disk_list = [x[:-1] for x in cmd_ret]
        return disk_list
    
    def get_system_info(self):
        obj = SystemInfo.objects.get(id='1')
        boot_time_timestamp = psutil.boot_time()
        boot_time = datetime.datetime.fromtimestamp(boot_time_timestamp)
        formatted_boot_time = boot_time.strftime("%Y-%m-%d %H:%M:%S")
    
        System_version = platform.platform()
        System_type = platform.system()
        Kernel_version = platform.uname().release


        with open('/proc/uptime', 'r') as f:  
            uptime_seconds = float(f.readline().split()[0])  
  
        # 将总秒数转换为天、小时、分钟和秒  
        days = int(uptime_seconds // (24 * 60 * 60))  
        uptime_seconds %= (24 * 60 * 60)  
        hours = int(uptime_seconds // (60 * 60))  
        uptime_seconds %= (60 * 60)  
        minutes = int(uptime_seconds // 60)  
        seconds = uptime_seconds % 60  

        # 使用format方法格式化输出，避免不必要的.0  
        uptime_str = "{:d} 天, {:d} 小时, {:d} 分钟".format(days, hours, minutes)  

        # 如果秒数不是整数，则添加秒数的格式化输出  
        if seconds != int(seconds):  
            uptime_str += ", {:.2f} 秒".format(seconds)  
        else:  
            uptime_str += ", {} 秒".format(int(seconds))  


        total = round(psutil.virtual_memory().total / (1024*1024),2)
        values = {
                "manufacturer": obj.manufacturer,
                "product_name": obj.product_name,
                "product_model": obj.product_model,
                "Software_version": VERSION,
                "System_version": System_version,
                "System_type": System_type,
                "Kernel_version": Kernel_version,
                "serial_number": obj.serial_number,
                "RAM": str(int(total)) + " MB",
                "on_time":formatted_boot_time,
                "up_time": uptime_str
            }
        return values
        # SystemInfo.objects.create(**values)
    
    def get_cpu_info(self):
        #cpu型号
        cmd = 'lscpu'
        (status, cpuinfo) = run_cmd(cmd)
        cpuinfo = cpuinfo.split('\n')
        for item in cpuinfo:
            if 'Model name' in item:
                cpuname = item
            elif '型号名称' in item:
                cpuname = item

        #cpu物理核心数
        cores = psutil.cpu_count(logical=False)

        #cpu逻辑核心数
        logical_cores = psutil.cpu_count()

        #cpu占用率
        usage = psutil.cpu_percent()

        sing_core = []

        #每个cpu核心的占用率
        for i , percent in enumerate(psutil.cpu_percent(percpu=True,interval=1)):
            sing_percent = "{:.2f}".format(percent)
            sing_cpu = 'cpu'+ str(i) + ' ' + sing_percent
            sing_core.append(sing_cpu)

        values = {
            "name": cpuname,
            "usage":usage,
        }

        # cpu_monitoring_data.objects.create(**values)

        return {'cpumodel':cpuname,'cores':cores,'logcores':logical_cores,'usage':usage,'sing_core':sing_core}


    def get_men_info(self):
        #获取内存总量
        total = round(psutil.virtual_memory().total / (1024*1024),2)
        #获取可用内存
        free = round(psutil.virtual_memory().free / (1024*1024),2)
        #获取当前已使用的内存
        used = round(psutil.virtual_memory().used / (1024*1024),2)
        #获取内存使用率
        mem_percent = psutil.virtual_memory().percent
        values = {
            "mem_percent": mem_percent,
        }
        # mem_monitoring_data.objects.create(**values)

        return {'total':round(total,2),'free':round(free,2),'used':round(used,2),'mem_percent':mem_percent}

    
    def get_diskio_info(self):
        #获取磁盘io情况
        old_io_counters = psutil.disk_io_counters()
        #获取单个磁盘的io情况
        old_io_perdisk = psutil.disk_io_counters(perdisk=True,nowrap=True)
        #获取网络的使用情况
        old_sing_network = psutil.net_io_counters(pernic=True)
        # 获取单网卡的使用情况
        old_network = psutil.net_io_counters()

        get_time = datetime.datetime.now()
        time_str = get_time.strftime("%H:%M:%S")

        # 等待一段时间
        time.sleep(3)

        # 获取另一个时间点的磁盘 I/O 信息
        new_io_counters = psutil.disk_io_counters()
        new_io_perdisk = psutil.disk_io_counters(perdisk=True,nowrap=True)
        # 获取另一个时间点的网络 I/O 信息
        new_sing_network = psutil.net_io_counters(pernic=True)

        read_count = new_io_counters.read_count - old_io_counters.read_count
        write_count = new_io_counters.write_count - old_io_counters.write_count
        read_speed = round((new_io_counters.read_bytes - old_io_counters.read_bytes) / (1024*1024),2)
        write_speed = round((new_io_counters.write_bytes - old_io_counters.write_bytes) / (1024*1024),2)
        write_time = new_io_counters.write_time - old_io_counters.write_time
        if write_count > 0 :
            write_delay = round(write_time / write_count,2)
        else:
            write_delay = 0

        read_total = round(new_io_counters.read_bytes / (1024*1024),2)
        write_total = round(new_io_counters.write_bytes / (1024*1024),2)

        # 计算每秒的磁盘 I/O 信息
        io_per_sec = {
            'read_count': read_count + write_count,
            'write_count': write_count,
            'read_speed': read_speed / 3,
            'write_speed': write_speed / 3,
            'write_delay':write_delay /3,
            'time_str':time_str,
            'read_total':read_total /3,
            'write_total':write_total /3,
        }
        # diskio_monitoring_data.objects.create(**io_per_sec)

        diskio_per_sec = {}
        logical_volumes = get_lv_disk_mapped()
        for disk,io1 in old_io_perdisk.items():
            io2 = new_io_perdisk[disk]
            disk_read_count = io2.read_count - io1.read_count
            disk_write_count = io2.write_count - io1.write_count
            disk_read_speed = round((io2.read_bytes - io1.read_bytes) / (1024*1024),2)
            disk_write_speed = round((io2.write_bytes - io1.write_bytes) / (1024*1024),2)
            read_total = round(io2.read_bytes / (1024*1024),2)
            write_total = round(io2.write_bytes / (1024*1024),2)
            write_time = io2.write_time - io1.write_time
            if disk_write_count > 0 :
                write_delay = round(write_time / disk_write_count,2)
            else:
                write_delay = 0
            diskinfo = {'read_count':(disk_read_count + disk_write_count) /3,'write_count':disk_write_count /3,
                        'read_speed':disk_read_speed / 3,'write_speed':disk_write_speed / 3,
                        'time_str':time_str,'read_total':read_total / 3,'write_total':write_total /3 ,
                        'write_delay':write_delay}
            disk = logical_volumes.get(disk, disk)
            diskio_per_sec[disk] = diskinfo

        # 计算每秒的网络速率
        net_speed = {}
        for interface in old_sing_network:
            if interface == 'lo':
                continue
            bytes_sent = new_sing_network[interface].bytes_sent - old_sing_network[interface].bytes_sent
            bytes_recv = new_sing_network[interface].bytes_recv - old_sing_network[interface].bytes_recv
            time_delta = 1  # 时间间隔为1秒
            sent_sing_speed = round((bytes_sent / time_delta) / (1024*1024),2)
            recv_sing_speed = round((bytes_recv / time_delta) / (1024*1024),2)
            sent_total = round(new_sing_network[interface].bytes_sent / (1024*1024),2)
            recv_total = round(new_sing_network[interface].bytes_recv / (1024*1024),2)

            netinfo = {'sent_speed':sent_sing_speed /3,'recv_speed':recv_sing_speed / 3,
                        'time_str':time_str,'sent_total':sent_total / 3,'recv_total':recv_total / 3}
            net_speed[interface] = netinfo

        # 获取另一个时间点的总网络 I/O 信息
        new_network = psutil.net_io_counters()

        # 计算每秒的总网络速率
        sent_speed = round((new_network.bytes_sent - old_network.bytes_sent) / (1024*1024),2)
        recv_speed = round((new_network.bytes_recv - old_network.bytes_recv) / (1024*1024),2)
        sent_total = round(new_network.bytes_sent / (1024*1024),2)
        recv_total = round(new_network.bytes_recv / (1024*1024),2)

        values = {
            'sent_speed':sent_speed /3,
            'recv_speed':recv_speed /3,
            'sent_total':sent_total /3,
            'recv_total':recv_total /3,
            'time_str':time_str,
        }

        # network_monitoring_data.objects.create(**values)


        return io_per_sec , diskio_per_sec,values,net_speed

   
    def getNicsUtil(self):
        net_stats = psutil.net_io_counters(pernic=True)
        read_bytes = {}
        write_bytes = {}
        
        for nic, stats in net_stats.items():
            read_bytes[nic] = stats.bytes_recv
            write_bytes[nic] = stats.bytes_sent
        
        # 等待1秒，然后再次获取网卡的统计信息
        # 计算读写字节数的差值，得到每秒的读写字节数
        psutil.wait_procs(psutil.process_iter(), timeout=2)
        new_net_stats = psutil.net_io_counters(pernic=True)
        
        read_bytes_per_sec = sum(stats.bytes_recv - read_bytes.get(nic, 0)
                                 for nic, stats in new_net_stats.items())/len(new_net_stats.items())
        write_bytes_per_sec = sum(stats.bytes_sent - write_bytes.get(nic, 0)
                                  for nic, stats in new_net_stats.items())/len(new_net_stats.items())
        max_read_bytes_per_sec = max(stats.bytes_recv - read_bytes.get(nic, 0)
                                     for nic, stats in new_net_stats.items())
        max_write_bytes_per_sec = max(stats.bytes_sent - write_bytes.get(nic, 0)
                                      for nic, stats in new_net_stats.items())
        avg_rw_bytes_per_sec = read_bytes_per_sec + write_bytes_per_sec
        max_rw_bytes_per_sec = max_read_bytes_per_sec + max_write_bytes_per_sec

        return (avg_rw_bytes_per_sec, max_rw_bytes_per_sec)

    def get_disk_util(self):
        partitions = psutil.disk_partitions()
        total_usage = 0
        total_used = 0
        total_size = 0
        format_string = "{:.2f}"

        
        
        usage = psutil.disk_usage('/')
        total_used += usage.used
        total_size += usage.total


        total_usage =  (total_used / total_size) * 100
        
        return (format_string.format(total_usage), total_size, total_used)


class OperationLogData(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'startDateTime': openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'endDateTime'  : openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'page': openapi.Schema(type=openapi.TYPE_INTEGER, description="从1开始"),
            'page_size': openapi.Schema(type=openapi.TYPE_INTEGER),
        },
        required=['startDateTime', 'endDateTime'],
    ))

    def post(self, request, *args, **kwargs):
        try:

            startDateTime = request.data.get('startDateTime')
            endDateTime = request.data.get('endDateTime')

            start = translateUTCOrLoaclTimeStringToLocalTime(startDateTime, TimeType.UTC)
            end   = translateUTCOrLoaclTimeStringToLocalTime(endDateTime, TimeType.UTC)
            logger.debug(f'开始时间：{start}')
            logger.debug(f'结束时间：{end}')
 
            page = WebPagination()
            query_set = OperationLog.objects.filter(created_at__gte=start, created_at__lte=end).order_by('-id')
            nodes = page.paginate_queryset(queryset=query_set, request=request, view=self)
            ser = OperationLogSerializer(instance=nodes, many=True, context={'request': request})
            return page.get_paginated_response(ser.data)
        except Exception as e:
            logger.error("get operation log error:%s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("GetOperatorLogError")
            return JSONResponse(ret)
        
        
    def get_object_list(self, request, page):
        try:
            query_set = OperationLog.objects.all()
            admin_users = page.paginate_queryset(queryset=query_set, request=request, view=self)
            return admin_users
        except Exception as e:
            raise Http404()
        

class deleteOperatorLog(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'startDateTime': openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'endDateTime'  : openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
        },
        required=['startDateTime', 'endDateTime'],
    ))

    def post(self, request, *args, **kwargs):
        try:

            startDateTime = request.data.get('startDateTime')
            endDateTime = request.data.get('endDateTime')

            start = translateUTCOrLoaclTimeStringToLocalTime(startDateTime, TimeType.UTC)
            end   = translateUTCOrLoaclTimeStringToLocalTime(endDateTime, TimeType.UTC)
            logger.debug(f'开始时间：{start}')
            logger.debug(f'结束时间：{end}')

            OperationLog.objects.filter(created_at__gte=start, created_at__lte=end).delete()
            ret = get_error_result("Success")
            return JSONResponse(ret)

        except Exception as e:
            logger.error("删除操作日志记录错误:%s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteOperatorLogError")
            return JSONResponse(ret)


from django.http import HttpResponse
from wsgiref.util import FileWrapper
import mimetypes
from django.core.files.storage import default_storage

RUN_LOG_DIR='./log'
TMP_RUN_LOG_DIR='./log/RUNLOG'
TAR_DIR='./log/runLog.tar.gz'

class unLoadRunLog(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'startDateTime': openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'endDateTime'  : openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
        },
        required=['startDateTime', 'endDateTime'],
    ))

    def post(self, request, *args, **kwargs):
        try:

            startDateTime = request.data.get('startDateTime')
            endDateTime = request.data.get('endDateTime')

            start = translateUTCOrLoaclTimeStringToLocalTime(startDateTime, TimeType.UTC)
            end   = translateUTCOrLoaclTimeStringToLocalTime(endDateTime, TimeType.UTC)
            logger.debug(f'开始时间：{start}')
            logger.debug(f'结束时间：{end}')

            logList = []
            currrentLogList = []
            pattern = re.compile('^\w+\.log\.\d{4}-\d{2}-\d{2}$')
            pattern2 = re.compile('^\w+\.log$')#当天日志
            files_and_directories = os.listdir(RUN_LOG_DIR)
            # 遍历文件和子目录
            for item in files_and_directories:
                item_path = os.path.join(RUN_LOG_DIR, item)

                # 检查是否是文件
                if os.path.isfile(item_path):
                    if pattern.match(item) != None:
                        logList.append(item_path)
                    elif pattern2.match(item) != None:
                        currrentLogList.append(item_path)
                    else:
                        pass

            
            logger.debug(f'以往的运行日志：{logList} {currrentLogList}') 
            filterLogList = []    
            for logName in logList:
                date = logName.split('log.')[1]
                date = date + ' 00:00:00'
                logTime = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
                if logTime >= start and logTime <= end:
                    filterLogList.append(logName)

            currentDate = datetime.datetime.now()
            if currentDate.date() >= start.date() and currentDate.date() <= end.date():
                for logName in currrentLogList:
                    filterLogList.append(logName)

            logger.debug(f'符合条件的以往的运行日志：{filterLogList}') 
            try:
                run_cmd(f'rm -fr {TMP_RUN_LOG_DIR}')
                os.mkdir(TMP_RUN_LOG_DIR)

            except OSError as error:
                logger.debug(f"创建临时目录失败: {error}")
                logger.error(''.join(traceback.format_exc()))
                ret = get_error_result("CreateTmpDirError")
                return JSONResponse(ret)

            for logName in filterLogList:
                status, res = run_cmd(f'cp {logName} {TMP_RUN_LOG_DIR}')
                if status != 0:
                    logger.debug(f"拷贝日志到{TMP_RUN_LOG_DIR}目录出错: {res}")
                    ret = get_error_result("CopyRunLogToTmpDirError")
                    return JSONResponse(ret)
            
            status, res = run_cmd(f'tar -cvzf {TAR_DIR} {TMP_RUN_LOG_DIR}')
            if status != 0:
                logger.debug(f"压缩{TMP_RUN_LOG_DIR}目录出错: {res}")
                ret = get_error_result("TarTmpDirError")
                return JSONResponse(ret)

            run_cmd(f'rm -fr {TMP_RUN_LOG_DIR}')


            with open(TAR_DIR, 'rb') as fh:
            # 获取文件的MIME类型
                file_mime_type = mimetypes.guess_type(TAR_DIR)[0] or 'application/octet-stream'

                if file_mime_type != 'application/x-gzip':
                    file_mime_type = 'application/x-gzip'

                # 创建一个HttpResponse对象，并使用FileWrapper包装文件对象
                response = HttpResponse(FileWrapper(fh), content_type=file_mime_type)

                # 设置HTTP头，以便浏览器能够正确处理文件下载
                response['Content-Disposition'] = 'attachment; filename="runLog.tar.gz"'
                response['Content-Length'] = os.path.getsize(TAR_DIR)  # 获取文件大小


                # 返回响应
                return response
            

        except Exception as e:
            logger.error("下载运行日志错误:%s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("UnloadRunLogrError")
            return JSONResponse(ret)
        


class deleteRunLog(APIView):

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'startDateTime': openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
            'endDateTime'  : openapi.Schema(type=openapi.TYPE_STRING, description="2024-04-05T16:00:00.000Z"),
        },
        required=['startDateTime', 'endDateTime'],
    ))

    def post(self, request, *args, **kwargs):
        try:

            startDateTime = request.data.get('startDateTime')
            endDateTime = request.data.get('endDateTime')

            start = translateUTCOrLoaclTimeStringToLocalTime(startDateTime, TimeType.UTC)
            end   = translateUTCOrLoaclTimeStringToLocalTime(endDateTime, TimeType.UTC)
            logger.debug(f'开始时间：{start}')
            logger.debug(f'结束时间：{end}')

            logList = []
            pattern = re.compile('^\w+\.log\.\d{4}-\d{2}-\d{2}$')
            files_and_directories = os.listdir(RUN_LOG_DIR)
            # 遍历文件和子目录
            for item in files_and_directories:
                item_path = os.path.join(RUN_LOG_DIR, item)

                # 检查是否是文件
                if os.path.isfile(item_path):
                    if pattern.match(item) != None:
                        logList.append(item_path)

            
            logger.debug(f'以往的运行日志：{logList}') 
            filterLogList = []    
            for logName in logList:
                date = logName.split('log.')[1]
                date = date + ' 00:00:00'
                logTime = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
                if logTime >= start and logTime <= end:
                    filterLogList.append(logName)

            logger.debug(f'符合条件的以往的运行日志：{filterLogList}') 
            

            for logName in filterLogList:
                run_cmd(f'rm -fr {logName}')

            run_cmd(f'rm -fr {TAR_DIR}')

            return JSONResponse("Success")

        except Exception as e:
            logger.error("删除运行日志错误:%s", e)
            logger.error(''.join(traceback.format_exc()))
            ret = get_error_result("DeleteRunLogrError")
            return JSONResponse(ret)


