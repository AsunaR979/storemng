from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5

class SystemInfo(models.Model):
    id = models.IntegerField(primary_key=True)
    manufacturer = models.CharField(max_length=100, null=False)
    product_name = models.CharField(max_length=100, null=False)
    product_model = models.CharField(max_length=100, null=False)
    Software_version = models.CharField(max_length=100, null=False)
    System_version = models.CharField(max_length=100, null=False)
    System_type = models.CharField(max_length=100, null=False)
    Kernel_version = models.CharField(max_length=100, null=False)
    serial_number = models.CharField(max_length=100, null=False)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'systeminfo'
        ordering = ['id']


