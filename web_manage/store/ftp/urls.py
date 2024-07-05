from django.urls import path
from web_manage.store.ftp import views

urlpatterns = [
    path('get_ftp', views.SftpDir.as_view(), name='get_ftp'),
    path('add_ftp', views.SftpDir.as_view(), name='add_ftp'),
    path('delete_ftp', views.SftpDir.as_view(), name='delete_ftp'),
    path('edit_ftp', views.SftpDir.as_view(), name='edit_ftp'),

]
