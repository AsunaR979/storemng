from django.urls import path
from . import views

urlpatterns = [
    path('lvCopy', views.LvCopyView.as_view(), name='lvCopy'),
]
