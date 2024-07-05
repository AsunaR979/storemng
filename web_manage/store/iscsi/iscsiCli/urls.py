from django.urls import path
from . import views

urlpatterns = [
    path('scan_target',views.ScanTarget.as_view(),name='scan_target'),
    path('get_all_sessions',views.GetAllSessions.as_view(),name='get_all_sessions'),
    path('create_session',views.CreateSession.as_view(),name='create_session'),
    path('delete_session',views.DeleteSession.as_view(),name='delete_session'),
    path('get_session_detail',views.GetSessionDetail.as_view(),name='get_session_detail'),
]
