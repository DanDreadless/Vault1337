from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from . import views

router = DefaultRouter()
router.register('files', views.FileViewSet, basename='file')
router.register('iocs', views.IOCViewSet, basename='ioc')
router.register('yara', views.YaraViewSet, basename='yara')

urlpatterns = [
    # Auth
    path('auth/register/', views.RegisterView.as_view(), name='api-register'),
    path('auth/token/', views.ThrottledTokenObtainPairView.as_view(), name='api-token-obtain'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='api-token-refresh'),
    path('auth/logout/', views.LogoutView.as_view(), name='api-logout'),
    path('auth/user/', views.UserDetailView.as_view(), name='api-user-detail'),
    # IP intelligence
    path('intel/ip/', views.IPCheckView.as_view(), name='api-ip-check'),
    # VT / MB downloads
    path('files/vt-download/', views.VTDownloadView.as_view(), name='api-vt-download'),
    path('files/mb-download/', views.MBDownloadView.as_view(), name='api-mb-download'),
    # Standalone tools
    path('tools/qr-decode/', views.QRDecodeView.as_view(), name='api-qr-decode'),
    # API key manager (staff only)
    path('admin/keys/', views.APIKeyView.as_view(), name='api-admin-keys'),
    # OpenAPI schema + Swagger UI
    path('schema/', SpectacularAPIView.as_view(), name='api-schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='api-schema'), name='api-docs'),
] + router.urls
