from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5


class ClusterNode(models.Model):
    id = models.IntegerField(primary_key=True)
    local_ip = models.GenericIPAddressField(protocol="ipv4", null=True)
    local_nic = models.CharField(max_length=200, null=False)
    host_name = models.CharField(max_length=200, null=False)
    ip = models.GenericIPAddressField(protocol="ipv4", null=True)
    status = models.IntegerField(null=False)
    double_control_status = models.CharField(max_length=200, null=False)
    is_auto_restore = models.BooleanField(default=True)
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'cluster_node'
        ordering = ['id']
