from django.urls import path, include
from . import views

# 配置当前web_manage下面的不同模块的路由
urlpatterns = [
    path('', include('web_manage.admin.urls')),
    path('index/', include('web_manage.index.urls')),
    path('sysmng/', include('web_manage.sysmng.urls')),
    path('hardware/', include('web_manage.hardware.urls')),
    path('hardware/raid/', include('web_manage.hardware.raid.urls')),
    path('store/nas/', include('web_manage.store.nas.urls')),
    path('store/ftp/', include('web_manage.store.ftp.urls')),
    path('store/nfs/', include('web_manage.store.nfs.urls')),
    path('store/samba/', include('web_manage.store.samba.urls')),    
    path('store/iscsiCli/', include('web_manage.store.iscsi.iscsiCli.urls')),    
    path('store/iscsiSrv/', include('web_manage.store.iscsi.iscsiSrv.urls')),    
    path('cluster/', include('web_manage.cluster.urls')),
    path('hardware/hardRaid/', include('web_manage.hardware.hardRaid.urls')),
    path('warn/', include('web_manage.warn.urls')),
    path('perfdata/', include('web_manage.perfdata.urls')),
]

