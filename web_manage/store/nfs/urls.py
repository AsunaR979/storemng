from django.urls import path
from web_manage.store.nfs import views

urlpatterns = [
    path('get_nfs', views.Getnfs.as_view(), name='nfs'),
    path('editor_nfs', views.Editor_nfs.as_view(),name='editor_nfs'),
    path('add_nfs',views.Add_nfs.as_view(),name='add_nfs'),
    path('delete_nfs',views.Delete_nfs.as_view(),name='delete_nfs'),
]
