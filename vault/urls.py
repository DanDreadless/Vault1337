from django.urls import path
from .views import vault_table

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('vault/', vault_table, name='vault_table'),
]