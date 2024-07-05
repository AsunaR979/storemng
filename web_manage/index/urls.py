from django.urls import path
from web_manage.index import views

urlpatterns = [
    path('get_HardDisk_info/', views.SystemHardDiskinfoData.as_view(), name='HardDisk-info-data'),
    path('get_top_data/', views.SystemMonitorTopData.as_view(), name='system-monitor-top-data'),
    path('get_operation_log/', views.OperationLogData.as_view(), name='operation-log-data'),
    path('deleteOperatorLog/', views.deleteOperatorLog.as_view(), name='deleteOperatorLog'),
    path('unLoadRunLog/', views.unLoadRunLog.as_view(), name='unLoadRunLog'),
    path('deleteRunLog/', views.deleteRunLog.as_view(), name='deleteRunLog'),
]
