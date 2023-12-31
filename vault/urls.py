from django.contrib.auth.views import LogoutView
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('vault/', views.vault_table, name='vault_table'),
    path('upload/', views.upload_file, name='upload_file'),
    path('urldownload/', views.get_webpage, name='get_webpage'),
    path('vtdownload/', views.vt_download, name='vt_download'),
    path('sample/<int:item_id>/', views.sample_detail, name='sample_detail'),
    path('registration/signup/', views.user_signup, name='user_signup'),
    path('login/', views.user_login, name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    # path('logged_out/', LogoutView.as_view(), name='logout'),
]