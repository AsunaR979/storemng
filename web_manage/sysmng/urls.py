from django.urls import path
from . import views

urlpatterns = [
    path('hostmng/operate/', views.HostmngView.as_view(), name='operate'),
    path('netmng/operate/', views.NetmngView.as_view(), name='operate'),
    path('srvmng/operate/', views.SrvmngView.as_view(), name='operate'),
    path('property/operate/', views.PropertyView.as_view(), name='operate'),
    path('vermng/operate/', views.VermngView.as_view(), name='operate'),
]
