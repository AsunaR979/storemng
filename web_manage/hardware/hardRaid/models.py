from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5

class hardRaidError(models.Model):
    id = models.IntegerField(primary_key=True)
    desc = models.CharField(max_length=256, null=False)

    class Meta:
        db_table = 'hardRaidError'
        ordering = ['id']