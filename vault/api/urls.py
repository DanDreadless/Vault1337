from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from . import views

router = DefaultRouter()
router.register('files', views.FileViewSet, basename='file')
router.register('iocs', views.IOCViewSet, basename='ioc')

urlpatterns = [
    # Auth
    path('auth/register/', views.RegisterView.as_view(), name='api-register'),
    path('auth/token/', TokenObtainPairView.as_view(), name='api-token-obtain'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='api-token-refresh'),
    path('auth/user/', views.UserDetailView.as_view(), name='api-user-detail'),
    # OpenAPI schema + Swagger UI
    path('schema/', SpectacularAPIView.as_view(), name='api-schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='api-schema'), name='api-docs'),
] + router.urls
