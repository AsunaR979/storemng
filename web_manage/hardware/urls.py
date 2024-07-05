from django.urls import path
from . import views
from . import auto_snap

urlpatterns = [
    path('lvm/vg/operate', views.VgMngView.as_view(), name='vg'),
    # path('lvm/pv/operate', views.PvMngView.as_view(), name='pv'),
    path('lvm/lv/operate', views.LvMngView.as_view(), name='lv'),
    path('lvm/autolv/operate', auto_snap.AutoSnapView.as_view(), name='autolv'),
]
