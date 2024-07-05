from rest_framework import serializers
from .models import *
from web_manage.common.utils import create_uuid,DateTimeFieldMix
import re


class AdminUserSerializer(serializers.ModelSerializer):
    """
    """
    deleted_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    updated_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    created_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)

    last_login = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    role_name = serializers.CharField(source='role.role', read_only=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = AdminUser
        fields = ("id", "username", "real_name", "email", "last_login", "login_ip", "is_superuser",
                  "is_active", "desc", "role", "role_name", "created_at", "updated_at", "deleted_at", "password")


class RoleSerializer(serializers.ModelSerializer):
    user_count = serializers.SerializerMethodField(read_only=True)
    is_super = serializers.SerializerMethodField(read_only=True)

    deleted_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    updated_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)
    created_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)

    class Meta:
        model = Role
        fields = '__all__'

    def get_user_count(self, instance):
        return instance.users.count()

    def get_is_super(self, instance):
        is_super = 0
        user = AdminUser.objects.filter(deleted=False, role=instance.id).first()
        if user and user.is_superuser:
            is_super = 1
        return is_super


class OperationLogSerializer(DateTimeFieldMix):

    class Meta:
        model = OperationLog
        fields = "__all__"

