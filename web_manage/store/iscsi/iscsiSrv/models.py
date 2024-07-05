from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5


class tgtdAccount(models.Model):
    id = models.IntegerField(primary_key=True)
    user = models.CharField(max_length=100)
    passwd = models.CharField(max_length=100)

    class Meta:
        db_table = 'tgtdAccount'
