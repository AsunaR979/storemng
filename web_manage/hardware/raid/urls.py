from django.urls import path
from . import views

urlpatterns = [
    path('getRaidInfoList/', views.GetRaidInfoListView.as_view(), name='getRaidInfoList'),
    path('rmRaids/', views.rmRaids.as_view(), name='rmRaids'),
    path('setGlobalSpare/', views.setGlobalSpare.as_view(), name='setGlobalSpare'),
    path('createRaid/', views.createRaid.as_view(), name='createRaid'),
    path('getFreeZone/', views.getFreeZone.as_view(), name='getFreeZone'),
    path('getFreeRaid/', views.getFreeRaid.as_view(), name='getFreeRaid'),
    path('getRaidDetail/', views.getRaidDetail.as_view(), name='getRaidDetail'),
    path('addHostToRaid/', views.addHostToRaid.as_view(), name='addHostToRaid'),
    path('delHostFromRaid/', views.delHostFromRaid.as_view(), name='delHostFromRaid'),
    path('faultyDevFromRaid/', views.faultyDevFromRaid.as_view(), name='faultyDevFromRaid'),
    path('recoverFaultyDevFromRaid/', views.recoverFaultyDevFromRaid.as_view(), name='recoverFaultyDevFromRaid'),
    path('removeFaultyDevFromRaid/', views.removeFaultyDevFromRaid.as_view(), name='removeFaultyDevFromRaid'),
    path('replaceChildDev/', views.replaceChildDev.as_view(), name='replaceChildDev'),
    path('growUpRaid/', views.growUpRaid.as_view(), name='growUpRaid'),
    path('getMailInfos/', views.getMailInfos.as_view(), name='getMailInfos'),
    path('updateMails/', views.updateMails.as_view(), name='updateMails'),
    path('updateMailsConfig/', views.updateMailsConfig.as_view(), name='updateMailsConfig'),
    path('removeDevFromRaid/', views.removeDevFromRaid.as_view(), name='removeDevFromRaid'),
]

