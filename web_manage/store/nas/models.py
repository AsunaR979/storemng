from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5

class NasUser(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100, null=False)
    user_group = models.CharField(max_length=100, null=False)
    type = models.CharField(max_length=100, null=False)
    pwd = models.CharField(max_length=200, null=False)
    is_smb = models.IntegerField(null=False)
    is_ftp = models.IntegerField(null=False)
    rsv1 = models.CharField(max_length=100, null=False)
    rsv2 = models.CharField(max_length=100, null=False)
    rsv3 = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'nas_user'
        ordering = ['id']

class NasDir(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100, null=False)
    dev_path = models.CharField(max_length=300, null=False)
    mountpoint = models.CharField(max_length=300, null=False)
    is_drbd = models.IntegerField(null=False)
    is_nfs = models.IntegerField(null=False)
    is_smb = models.IntegerField(null=False)
    # ftp_user_id = models.IntegerField(null=True)
    nas_user = models.ForeignKey(NasUser, on_delete=models.SET_NULL, db_column="ftp_user_id", null=True)
    is_ftp_active = models.IntegerField(null=False)
    rsv1 = models.CharField(max_length=100, null=False)
    rsv2 = models.CharField(max_length=100, null=False)
    rsv3 = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'nas_dir'
        ordering = ['id']