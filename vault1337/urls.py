"""
URL configuration for vault1337 project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('vault.api.urls')),
]

# PSA social auth URLs — only registered when SSO is enabled and the package
# is installed (settings.py guards SSO_ENABLED=False on ImportError).
if getattr(settings, 'SSO_ENABLED', False):
    from vault.sso_views import SSOCompleteView, SSOErrorView
    urlpatterns += [
        path('social/', include('social_django.urls', namespace='social')),
        path('sso/complete/', SSOCompleteView.as_view(), name='sso-complete'),
        path('sso/error/', SSOErrorView.as_view(), name='sso-error'),
    ]

urlpatterns += [
    # React SPA catch-all — must be last.
    # Serves frontend/dist/index.html for any route not matched above.
    re_path(
        r'^(?!api/|admin/|static/|social/|sso/).*$',
        TemplateView.as_view(template_name='index.html'),
        name='react-app',
    ),
]