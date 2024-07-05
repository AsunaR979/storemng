from django.urls import path
from . import views

urlpatterns = [
    path('hostconf', views.HostconfView.as_view(), name='hostconf'),
    path('peerconf', views.PeerconfView.as_view(), name='hostconf'),
    path('srvMng', views.SrvMngView.as_view(), name='srvMng'),
    path('heartbeat', views.HeartbeatView.as_view(), name='heartbeat'),
    path('virtualIp', views.VirtualIpView.as_view(), name='virtualIp'),
    path('pingNode', views.PingNodeView.as_view(), name='pingNode'),
    path('copyLv', views.CopyLvView.as_view(), name='copyLv'),        
]
