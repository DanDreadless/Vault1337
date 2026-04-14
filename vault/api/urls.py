from django.urls import path
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from . import views

router = DefaultRouter()
router.register('files', views.FileViewSet, basename='file')
router.register('iocs', views.IOCViewSet, basename='ioc')
router.register('yara', views.YaraViewSet, basename='yara')
router.register('admin/users', views.UserManagementViewSet, basename='admin-user')
router.register('admin/roles', views.RoleViewSet, basename='admin-role')

urlpatterns = [
    # Health probe (unauthenticated — for load balancers and container health checks)
    path('health/', views.HealthView.as_view(), name='api-health'),
    # Auth
    path('auth/register/', views.RegisterView.as_view(), name='api-register'),
    path('auth/token/', views.ThrottledTokenObtainPairView.as_view(), name='api-token-obtain'),
    path('auth/token/refresh/', views.CookieTokenRefreshView.as_view(), name='api-token-refresh'),
    path('auth/token/set-cookie/', views.SetRefreshCookieView.as_view(), name='api-token-set-cookie'),
    path('auth/logout/', views.LogoutView.as_view(), name='api-logout'),
    path('auth/user/', views.UserDetailView.as_view(), name='api-user-detail'),
    path('auth/password-reset/', views.PasswordResetRequestView.as_view(), name='api-password-reset'),
    path('auth/password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='api-password-reset-confirm'),
    # SSO config (public) + code exchange
    path('auth/sso/config/', views.SSOConfigView.as_view(), name='api-sso-config'),
    path('auth/sso/exchange/', views.SSOExchangeView.as_view(), name='api-sso-exchange'),
    # IP / domain intelligence
    path('intel/ip/', views.IPCheckView.as_view(), name='api-ip-check'),
    path('intel/domain/', views.DomainCheckView.as_view(), name='api-domain-check'),
    # VT / MB downloads
    path('files/vt-download/', views.VTDownloadView.as_view(), name='api-vt-download'),
    path('files/mb-download/', views.MBDownloadView.as_view(), name='api-mb-download'),
    # Standalone tools
    path('tools/qr-decode/', views.QRDecodeView.as_view(), name='api-qr-decode'),
    # API key manager (staff only)
    path('admin/keys/', views.APIKeyView.as_view(), name='api-admin-keys'),
    # App settings (staff only)
    path('admin/settings/', views.AppSettingsView.as_view(), name='api-admin-settings'),
    path('admin/permissions/', views.AvailablePermissionsView.as_view(), name='api-admin-permissions'),
    # Management dashboard + CyberChef management (staff only)
    path('admin/dashboard/', views.DashboardStatsView.as_view(), name='api-admin-dashboard'),
    path('admin/cyberchef/version/', views.CyberChefVersionView.as_view(), name='api-admin-cyberchef-version'),
    path('admin/cyberchef/update/', views.CyberChefUpdateView.as_view(), name='api-admin-cyberchef-update'),
    # Database backup (staff only)
    path('admin/backup/status/', views.BackupStatusView.as_view(), name='api-admin-backup-status'),
    path('admin/backup/db/', views.BackupRunView.as_view(), name='api-admin-backup-db'),
    # Audit log (staff only)
    path('admin/audit/', views.AuditLogView.as_view(), name='api-admin-audit'),
    path('admin/audit/purge/', views.AuditPurgeView.as_view(), name='api-admin-audit-purge'),
    # Account lockout (staff only)
    path('admin/auth/lockouts/', views.LockoutView.as_view(), name='api-admin-lockouts'),
    # Application version, update, and migration management (staff only)
    path('admin/app/version/', views.AppVersionView.as_view(), name='api-admin-app-version'),
    path('admin/app/update/', views.AppUpdateView.as_view(), name='api-admin-app-update'),
    path('admin/app/migrations/', views.AppMigrationStatusView.as_view(), name='api-admin-app-migrations'),
    path('admin/app/migrate/', views.AppMigrateView.as_view(), name='api-admin-app-migrate'),
    path('admin/app/makemigrations/', views.AppMakeMigrationsView.as_view(), name='api-admin-app-makemigrations'),
    # SSO admin config (staff only)
    path('admin/sso/', views.SSOAdminView.as_view(), name='api-admin-sso'),
    # OpenAPI schema + Swagger UI
    path('schema/', SpectacularAPIView.as_view(), name='api-schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='api-schema'), name='api-docs'),
] + router.urls
