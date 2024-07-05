from django.db import models

class CopyLvAsyncTask(models.Model):
    id = models.IntegerField(primary_key=True)
    resname = models.CharField(max_length=100, null=False)
    period = models.CharField(max_length=10, null=False)
    hour = models.CharField(max_length=10, null=False)
    minute = models.CharField(max_length=10, null=False)
    day = models.CharField(max_length=10, null=False)
    day_of_week = models.CharField(max_length=50, null=False)
    timeout_hours = models.CharField(max_length=10, null=False)
    rsv1 = models.TextField(blank=True, null=True)
    rsv2 = models.TextField(blank=True, null=True)
    rsv3 = models.TextField(blank=True, null=True)   
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'copy_lv_async_task'
        ordering = ['id']
        constraints = [  
            models.UniqueConstraint(fields=['resname'], name='unique_resname'),  
        ]  