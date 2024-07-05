from django.urls import path
from . import views

urlpatterns = [
    path('getScsiAllInformation/', views.getTheScsiAllInformation.as_view(), name='getScsiAllInformation/'),
    path('getFreeResourcesForScsi/', views.getFreeResourcesForScsi.as_view(), name='getFreeResourcesForScsi/'),
    path('iscsiDelTargetAccount/', views.iscsiDelTargetAccount.as_view(), name='iscsiDelTargetAccount/'),
    path('createTarget/', views.createTarget.as_view(), name='createTarget/'),
    path('deleteTarget/', views.deleteTarget.as_view(), name='deleteTarget/'),
    path('addTargetLun/', views.addTargetLun.as_view(), name='addTargetLun/'),
    path('setPermitHostAccess/', views.setPermitHostAccess.as_view(), name='setPermitHostAccess/'),
    path('deleteTargetLun/', views.deleteTargetLun.as_view(), name='deleteTargetLun/'),
    path('addTargetAccount/', views.addTargetAccount.as_view(), name='addTargetAccount/'),
    path('iscsiActive/', views.iscsiActive.as_view(), name='iscsiActive/'),
    path('getAllAccountList/', views.getAllAccountList.as_view(), name='getAllAccountList/'),
    path('addAccountToIscsi/', views.addAccountToIscsi.as_view(), name='addAccountToIscsi/'),
    path('deleteAccountFromIscsi/', views.deleteAccountFromIscsi.as_view(), name='deleteAccountFromIscsi/'),
]


