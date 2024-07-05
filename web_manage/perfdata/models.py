from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5

class CpuMonitoringData(models.Model):
    id = models.IntegerField(primary_key=True)
    usage = models.CharField(max_length=100, null=False)
    date_str = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'cpu_monitoring_data'
        ordering = ['id']

class MemMonitoringData(models.Model):
    id = models.IntegerField(primary_key=True)
    mem_percent = models.CharField(max_length=100, null=False)
    date_str = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'mem_monitoring_data'
        ordering = ['id']

class DiskioMonitoringData(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100, null=False)
    date_str = models.CharField(max_length=100, null=False)
    read_count = models.CharField(max_length=100, null=False)
    read_speed = models.CharField(max_length=100, null=False)
    write_speed = models.CharField(max_length=100, null=False)
    write_delay = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'diskio_monitoring_data'
        ordering = ['id']

class NetworkMonitoringData(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100, null=False)
    date_str = models.CharField(max_length=100, null=False)
    sent_speed = models.CharField(max_length=100, null=False)
    recv_speed = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'network_monitoring_data'
        ordering = ['id']

class SysMonitoy(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100, null=False)
    interval_mins = models.CharField(max_length=100, null=False)
    save_days = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'sys_monitor'
        ordering = ['id']
  
