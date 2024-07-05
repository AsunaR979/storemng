
import datetime
import logging
import sqlite3
from storesys.settings import  TIME_ZONE, scheduler
import traceback

from django.utils import timezone
import pytz
from rest_framework.views import APIView
from venv import logger
from django.utils import timezone
from storesys.settings import TIME_ZONE
from web_manage.common.errcode import get_error_result
from web_manage.common.utils import JSONResponse
from web_manage.perfdata.models import CpuMonitoringData, DiskioMonitoringData, MemMonitoringData, NetworkMonitoringData, SysMonitoy

class GetSettingInfo(APIView):
    def get(self,request,*args,**kwargs):
        
        try:
            resp =get_error_result("Success")
            
            interval_mins = '0'
            save_days = '0'

            allRecord = SysMonitoy.objects.all()
            if len(allRecord) <= 0:
                pass
            else:
                interval_mins = allRecord[0].interval_mins
                save_days = allRecord[0].save_days

            data = {
                'interval_mins':interval_mins,
                'save_days':save_days
            }

            resp['data'] = data
            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("SettingMonitorError")
            return JSONResponse(resp)


class GetMonitorData(APIView):
    def post(self,request,*args,**kwargs):
        try:
            target_tz = pytz.timezone(TIME_ZONE)
            resp =get_error_result("Success")
            time = request.data.get("time")
            select = request.data.get("select")
            name = request.data.get("name")


            start_datetime = datetime.datetime.fromisoformat(time[0].replace('Z','+00:00'))
            end_datetime = datetime.datetime.fromisoformat(time[1].replace('Z','+00:00'))
            start_datetime = start_datetime.astimezone(target_tz)
            end_datetime = end_datetime.astimezone(target_tz)


            cpudata =  self.get_cpu_data(start_datetime,end_datetime)
            memdata =  self.get_mem_data(start_datetime,end_datetime)
            diskiodata = self.get_diskio_data(start_datetime,end_datetime,name)
            networkdata = self.get_network_data(start_datetime,end_datetime,name)
            
            if select == 'disk':
                diskiodata = self.get_diskio_data(start_datetime,end_datetime,name)
            elif select == 'network':
                networkdata = self.get_network_data(start_datetime,end_datetime,name)

            resp['data'] = {'cpudata':cpudata,'memdata':memdata,'diskiodata':diskiodata,'networkdata':networkdata}
            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetMonitorfoError")
            return JSONResponse(resp)

    def get_cpu_data(self,time1,time2):
        try:
            cpudata = CpuMonitoringData.objects.filter(created_at__gte=time1, created_at__lt=time2).order_by('created_at')
            # 获取设置时区  
            target_tz = pytz.timezone(TIME_ZONE)
            backdata = []
            for item in cpudata:
                time = item.created_at.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")
                usage = float(item.usage)
                data = {
                    'usage':usage,
                    'time_str':time,
                }
                backdata.append(data)
        
            return backdata
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetCpuInfoError")
            return JSONResponse(resp)
    
    def get_mem_data(self,time1,time2):
        try:
            # 获取设置时区
            target_tz = pytz.timezone(TIME_ZONE)
            cpudata = MemMonitoringData.objects.filter(created_at__gte=time1, created_at__lt=time2).order_by('created_at')

            backdata = []
            for item in cpudata:
                time = item.created_at.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")
                mem_percent = float(item.mem_percent)
                data = {
                    'usage':mem_percent,
                    'time_str':time,
                }
                backdata.append(data)

            return backdata
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetMemoryInfoError")
            return JSONResponse(resp)
    
    def get_diskio_data(self,time1,time2,name):
        try:
        # 获取设置时区
            target_tz = pytz.timezone(TIME_ZONE)

            cpudata = DiskioMonitoringData.objects.filter(created_at__gte=time1, created_at__lt=time2,name=name).order_by('created_at')

            backdata = []
            for item in cpudata:
                time = item.created_at.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")
                read_count = float(item.read_count)
                read_speed = float(item.read_speed)
                write_speed = float(item.write_speed)
                write_delay = float(item.write_delay)
                data = {
                    'read_count':read_count,
                    'read_speed':read_speed,
                    'write_speed':write_speed,
                    'write_delay':write_delay,
                    'time_str':time,
                }
                backdata.append(data)
        
            return backdata
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetDiskioInfoError")
            return JSONResponse(resp)
    
    def get_network_data(self,time1,time2,name):
        try:
            # 获取设置时区
            target_tz = pytz.timezone(TIME_ZONE)

            cpudata = NetworkMonitoringData.objects.filter(created_at__gte=time1, created_at__lt=time2,name=name).order_by('created_at')

            backdata = []
            for item in cpudata:
                time = item.created_at.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")
                sent_speed = float(item.sent_speed)
                recv_speed = float(item.recv_speed)
                data = {
                    'sent_speed':sent_speed,
                    'recv_speed':recv_speed,
                    'time_str':time,
                }
                backdata.append(data)

            return backdata
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("GetNetworkInfoError")
            return JSONResponse(resp)
    

class SetMonitor(APIView):
    def post(self,request,*args,**kwargs):
        
        try:

            resp =get_error_result("Success")
            select = request.data.get("select")
            interval_mins = request.data.get("interval_mins")
            save_days = request.data.get("save_days")

            status, resp, mins, days = self.delete_stetiings()#始终维持一条记录
            if status == False:
                resp = get_error_result("SettingMonitorError")
                return JSONResponse(resp)

            if select == 'days':
                resp =  self.edit_sqlitdays(save_days, mins)
            elif select == 'mins':
                resp = self.create_stetiings(interval_mins, days)

            return JSONResponse(resp)
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("SettingMonitorError")
            return JSONResponse(resp)

    def delete_stetiings(self):
        try:

            status = True
            interval_mins = '0'
            days = '0'

            resp =get_error_result("Success")

            allRecord = SysMonitoy.objects.all()

            if len(allRecord) > 0:
                interval_mins = allRecord[0].interval_mins
                days = allRecord[0].save_days

            for record in allRecord:
                record.delete()
          
            return status, resp, interval_mins, days
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("DeleteMonitorQuestError")
            status = False
            return status, resp, interval_mins, days

    def create_stetiings(self, mins, days):
        try:
            resp = get_error_result("Success")

            updated_at = datetime.datetime.now()
            created_at = updated_at

            SysMonitoy.objects.create(name='Monitor', interval_mins=mins, save_days=days, updated_at=updated_at, created_at=created_at)

            # from storesys.perfData import MonitorDataEntry
            # scheduler.add_job(MonitorDataEntry().fill_monitor_data, 'interval', id='Monitor', seconds=mins, coalesce=True, max_instances=1)

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("CreateMonitorQuestError")
            return resp

    def edit_sqlitdays(self, days, mins):
        try:
            resp =get_error_result("Success")

            updated_at = datetime.datetime.now()
            created_at = updated_at

            SysMonitoy.objects.create(name='Monitor', interval_mins=mins, save_days=days, updated_at=updated_at, created_at=created_at)

            # from storesys.perfData import MonitorDataEntry
            # scheduler.add_job(MonitorDataEntry().fill_monitor_data, 'interval', id='Monitor', seconds=mins, coalesce=True, max_instances=1)

            return resp
        except Exception as err:
            logger.error(''.join(traceback.format_exc()))
            resp = get_error_result("EditMonitorDaysError")
            return resp
    
import time, threading
from storesys.perfData import MonitorDataEntry

def circleMonitorthread():

    defaultTime = 60
    monitorDataEntry = MonitorDataEntry()
    while(True):
        try:
            print('系统监控线程 ...')

            monitorDataEntry.fill_monitor_data()

            allRecord = SysMonitoy.objects.all()
            if len(allRecord) <= 0:
                defaultTime = 60
            else:
                interval_mins = allRecord[0].interval_mins
                defaultTime = int(interval_mins) * 60
        
            time.sleep(defaultTime)

        except Exception as e:
            logger.error(''.join(traceback.format_exc()))

        

        
thread2 = threading.Thread(target=circleMonitorthread)
thread2.start()


