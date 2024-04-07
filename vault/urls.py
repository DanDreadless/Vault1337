from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path ('home/', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('vault/', views.vault_table, name='vault_table'),
    path('upload/', views.upload_file, name='upload_file'),
    path('urldownload/', views.get_webpage, name='get_webpage'),
    path('vtdownload/', views.vt_download, name='vt_download'),
    path('mbdownload/', views.mb_download, name='mb_download'),
    path('sample/<int:item_id>', views.sample_detail, name='sample_detail'),
    path('tool_view/<int:item_id>', views.tool_view, name='tool_view'),
    path('delete_item/<int:item_id>/', views.delete_item, name='delete_item'),
    path('registration/signup/', views.user_signup, name='user_signup'),
    path('login/', views.user_login, name='login'),
]