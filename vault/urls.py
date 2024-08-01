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
    path('ipcheck/', views.ip_check, name='ip_check'),  
    path('sample/<int:item_id>', views.sample_detail, name='sample_detail'),
    path('tool_view/<int:item_id>', views.tool_view, name='tool_view'),
    path('delete_item/<int:item_id>/', views.delete_item, name='delete_item'),
    path('registration/signup/', views.user_signup, name='user_signup'),
    path('login/', views.user_login, name='login'),
    path('download-zipped-sample/<int:item_id>/', views.download_zipped_sample, name='download_zipped_sample'),
    path('yara/', views.yara, name='yara'),
    path('edit/<str:file_name>/', views.edit_yara_rule, name='edit_yara_rule'),
    path('delete/<str:file_name>/', views.delete_yara_rule, name='delete_yara_rule'),
    path('add_tag/<int:item_id>/', views.add_tag, name='add_tag'),
    path('remove_tag/<int:item_id>/', views.remove_tag, name='remove_tag'),
]