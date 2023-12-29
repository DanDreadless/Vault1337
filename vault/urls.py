from django.urls import path
from .views import vault_table, upload_file

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('vault/', vault_table, name='vault_table'),
    path('upload/', upload_file, name='upload_file'),
    # path('upload/upload_success/', upload_file, name='upload_success'),
]