from django.urls import path
from web_manage.store.nas import views

urlpatterns = [
    path('nas_user', views.NasUserMng.as_view(), name='nas_user'),
    path('get_mount_user', views.NasClientMng.as_view(), name='get_mount_user'),
    path('get_nas_user', views.NasUserMng.as_view(), name='get_nas_user'),
    path('nas_dir', views.NasDirMng.as_view(), name='nas_dir'),
    path('get_nas_dir', views.NasDirMng.as_view(), name='get_nas_dir'),
]
