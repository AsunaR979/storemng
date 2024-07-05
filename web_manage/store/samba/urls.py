from django.urls import path
from web_manage.store.samba import views

urlpatterns = [
    path('get_smb',views.SambaDir.as_view(),name='samba'),
    path('add_smb',views.SambaDir.as_view(),name='add_smb'),
    path('editor_smb',views.SambaDir.as_view(),name='editor_smb'),
    path('delete_smb',views.SambaDir.as_view(),name='delete_smb'),

    path('get_user',views.SambaDir.as_view(),name='user'),
    path('add_user',views.SambaDir.as_view(),name='add_user'),
    path('delete_user',views.SambaDir.as_view(),name='delete_user'),
]
