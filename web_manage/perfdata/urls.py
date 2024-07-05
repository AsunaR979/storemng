from django.urls import path
from web_manage.perfdata import views

urlpatterns = [
    path('getsettinginfo/',views.GetSettingInfo.as_view(), name='monitor'),
    path('getmonitordata/',views.GetMonitorData.as_view(), name='monitor'),
    path('setmonitor/',views.SetMonitor.as_view(), name='set_monitor'),
]
