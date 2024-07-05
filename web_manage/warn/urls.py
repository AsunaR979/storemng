from django.urls import path
from . import views

urlpatterns = [
    path('warnInfoShow/', views.warnInfoShowView.as_view(), name='warnInfoShow'),
    path('setWarnLevel/', views.setWarnLevel.as_view(), name='setWarnLevel'),
    path('getMailsAndSmtpServerInfo/', views.getMailsAndSmtpServerInfo.as_view(), name='getMailsAndSmtpServerInfo'),
    path('setSmtpServerInfo/', views.setSmtpServerInfo.as_view(), name='setSmtpServerInfo'),
    path('addMail/', views.addMail.as_view(), name='addMail'),
    path('deleteMailRecord/', views.deleteMailRecord.as_view(), name='deleteMailRecord'),
    path('eventClassificationStatistics/', views.eventClassificationStatistics.as_view(), name='eventClassificationStatistics'),
    path('hadViewed/', views.hadViewed.as_view(), name='hadViewed'),
    path('deleteWarnTableRecord/', views.deleteWarnTableRecord.as_view(), name='deleteWarnTableRecord'),
    path('testMail/', views.testMail.as_view(), name='testMail'),
]
