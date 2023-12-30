from django.urls import path
from .views import vault_table, upload_file, sample_detail, get_webpage

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('vault/', vault_table, name='vault_table'),
    path('upload/', upload_file, name='upload_file'),
    path('urldownload/', get_webpage, name='get_webpage'),
    path('sample/<int:item_id>/', sample_detail, name='sample_detail'),
    # path('upload/upload_success/', upload_file, name='upload_success'),
]