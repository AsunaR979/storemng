from django.urls import path, include
from . import views

# 配置当前cluster目录下的不同模块的路由：双控设置、双控存储
urlpatterns = [
    path('doubleCtlSetting/', include('web_manage.cluster.keepalived.urls')),
    path('doubleCtlStore/', include('web_manage.cluster.drbd.urls')),
]

