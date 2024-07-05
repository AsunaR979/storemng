from django.urls import path
from . import views

urlpatterns = [
    path('auth/', views.AuthView.as_view(), name='auth'),
    path('modifyPasswd/', views.AdminUsersView.as_view(), name='modifyPasswd'),
    path('activate/', views.ActivateMngView.as_view(), name='activateSoft'),
]
