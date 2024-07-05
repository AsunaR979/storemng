from django.db import models


class warnRecord(models.Model):
    uuid = models.CharField(max_length=100, primary_key=True)
    level = models.IntegerField(default=0)
    time = models.DateTimeField(auto_now_add=True)
    desc = models.TextField()
    hadNotified = models.IntegerField(default=0)

    class Meta:
        db_table = 'warnRecord'
        ordering = ['uuid']


class warnSet(models.Model):
    id = models.IntegerField(primary_key=True)
    warnLevel =  models.IntegerField(default=0)
    setTime = models.DateTimeField(auto_now_add=True)
    class Meta:
        db_table = 'warnSet'


class mails(models.Model):
    mail = models.CharField(max_length=100, primary_key=True)
    class Meta:
        db_table = 'mails'
    


class smtpSet(models.Model):
    id = models.IntegerField(primary_key=True)
    SMTPServer = models.CharField(max_length=100)
    SMTPPort = models.CharField(max_length=100)
    sendMail = models.CharField(max_length=100)
    SMTPUser = models.CharField(max_length=100)
    SMTPPasswd = models.CharField(max_length=100)
    class Meta:
        db_table = 'smtpSet'



class warnQueryPositionRecord(models.Model):
    tableName = models.CharField(max_length=100, primary_key=True)
    position = models.CharField(max_length=100)#该字段必须唯一且是递增(可能是id，可能是时间)
    class Meta:
        db_table = 'warnQueryPositionRecord'