from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5

class LvInfo(models.Model):
    id = models.IntegerField(primary_key=True)
    lvname = models.CharField(max_length=100, null=False)
    vgname = models.CharField(max_length=100, null=False)
    path = models.CharField(max_length=500, null=False)
    store_type = models.CharField(max_length=20, default='other')  # 'nas', 'san', 'other'
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'lv_info'
        ordering = ['id']


class AutoSnapTask(models.Model):
    id = models.IntegerField(primary_key=True)
    tsknm = models.CharField(max_length=100, null=False)
    lvname = models.CharField(max_length=100, null=False)
    vgname = models.CharField(max_length=100, null=False)
    size = models.CharField(max_length=100, null=False)
    interval = models.CharField(max_length=100, null=False)
    period = models.CharField(max_length=100, null=False)
    stdtime = models.DateTimeField(blank=True, null=False)
    endtime = models.DateTimeField(blank=True, null=False)
    svnum = models.CharField(max_length=100, null=False)
    is_loop_write = models.IntegerField(null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'auto_snap_task'
        ordering = ['id']