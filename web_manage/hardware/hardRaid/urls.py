from django.urls import path
from . import views

urlpatterns = [
    path('getControllers/', views.getControllers.as_view(), name='getControllers'),
    path('getSpecificPhysicalDisk/', views.getSpecificPhysicalDisk.as_view(), name='getSpecificPhysicalDisk'),
    path('getPhysicalDisks/', views.getPhysicalDisks.as_view(), name='getPhysicalDisks'),
    path('getSpecificLogicDisks/', views.getSpecificLogicDisks.as_view(), name='getSpecificLogicDisks'),
    path('getLogicDisks/', views.getLogicDisks.as_view(), name='getLogicDisks'),
    path('calcMaxArrayCapacity/', views.calcMaxArrayCapacity.as_view(), name='calcMaxArrayCapacity'),
    path('createHardRaid/', views.createHardRaid.as_view(), name='createHardRaid'),
    path('deleteHardRaid/', views.deleteHardRaid.as_view(), name='deleteHardRaid'),
    path('secureDeleteHardRaid/', views.secureDeleteHardRaid.as_view(), name='secureDeleteHardRaid'),
    path('reScan/', views.reScan.as_view(), name='reScan'),
    path('checkData/', views.checkData.as_view(), name='checkData'),
    path('setArrayState/', views.setArrayState.as_view(), name='setArrayState'),
    path('setArrayPara/', views.setArrayPara.as_view(), name='setArrayPara'),
    path('transform/', views.transform.as_view(), name='transform'),
    path('initDisk/', views.initDisk.as_view(), name='initDisk'),
    path('initDiskList/', views.initDiskList.as_view(), name='initDiskList'),
    path('addSpare/', views.addSpare.as_view(), name='addSpare'),
    path('removeSpare/', views.removeSpare.as_view(), name='removeSpare'),
    path('getSpecificDiskSmart/', views.getSpecificDiskSmart.as_view(), name='getSpecificDiskSmart'),
]
