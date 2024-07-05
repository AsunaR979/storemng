from django.db import models
from web_manage.common.utils import SoftDeletableModel, create_md5


class Role(SoftDeletableModel):
    id = models.IntegerField(primary_key=True)
    role = models.CharField(unique=True, max_length=64)

    menus = models.ManyToManyField('MenuPermission', through='RolePermission')
    enable = models.IntegerField(default=0)
    default = models.IntegerField(default=0)
    desc = models.CharField(blank=True, max_length=200)
    updated_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        # managed = False
        db_table = 'role'
        ordering = ['id']


class AdminUser(SoftDeletableModel):
    id = models.IntegerField(primary_key=True)
    username = models.CharField(unique=True, max_length=32)
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    login_ip = models.CharField(max_length=20, default='', blank=True)
    real_name = models.CharField(max_length=32, default='', null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE,
                             db_column='role_id', related_name='users', null=True)
    email = models.CharField(max_length=128, default='', null=True, blank=True)
    is_superuser = models.IntegerField(default=0)
    is_active = models.IntegerField(default=1)
    desc = models.CharField(blank=True, max_length=200)
    # deleted = models.IntegerField(default=0)
    # deleted_at = models.DateTimeField(blank=True, null=True)

    updated_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        # managed = False
        db_table = 'admin_user'
        ordering = ['id']

    def validate_password(self, _password):
        #print(create_md5(_password))
        return self.password == create_md5(_password)

    def set_password(self, password):
        self.password = create_md5(password)


class MenuPermission(SoftDeletableModel):
    id = models.IntegerField(primary_key=True)
    pid = models.BigIntegerField()
    type = models.IntegerField()
    title = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    component = models.CharField(max_length=255)
    bread_num = models.IntegerField()
    menu_sort = models.IntegerField()
    icon_show = models.CharField(max_length=255)
    icon_click = models.CharField(max_length=255)
    path = models.CharField(max_length=255)
    redirect = models.CharField(max_length=255)
    login = models.IntegerField(default=1)
    hidden = models.IntegerField(default=0)
    permission = models.CharField(max_length=255)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        db_table = 'menu_permission'


class RolePermission(models.Model):
    id = models.IntegerField(primary_key=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    menu = models.ForeignKey(MenuPermission, on_delete=models.CASCADE)

    class Meta:
        db_table = 'role_permission'
    objects = models.Manager


class OperationLog(models.Model):
    id = models.IntegerField(primary_key=True)
    user_id = models.IntegerField(null=True)
    user_name = models.CharField(max_length=200, null=False)
    user_ip = models.GenericIPAddressField(protocol="ipv4", null=True)
    content = models.TextField()
    result = models.TextField()
    module = models.CharField(max_length=255)
    updated_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'operation_log'
        ordering = ['-created_at', 'id']


class AuthorizationInfo(models.Model):
    id = models.IntegerField(primary_key=True)
    key1 = models.TextField(null=False)
    key2 = models.TextField(null=False)
    key3 = models.TextField(null=False)
    token = models.TextField(null=False)
    rsv1 = models.TextField(blank=True, null=True)
    rsv2 = models.TextField(blank=True, null=True)
    rsv3 = models.TextField(blank=True, null=True)    
    updated_at = models.DateTimeField(blank=True, null=True, auto_now=True)
    created_at = models.DateTimeField(blank=True, auto_now_add=True)

    class Meta:
        db_table = 'authorization_info'
        ordering = ['id']
