"""
Django settings for vault1337 project.
"""
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# -------------------- CORE SETTINGS --------------------

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured(
        "SECRET_KEY is not set. Add SECRET_KEY=<random-value> to your .env file."
    )

# False by default — set DEBUG=True in .env for local development only.
DEBUG = os.getenv('DEBUG', 'False') == 'True'

# Comma-separated list in .env: ALLOWED_HOSTS=127.0.0.1,yourdomain.com
ALLOWED_HOSTS = [h.strip() for h in os.getenv('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') if h.strip()]


# -------------------- INSTALLED APPS --------------------

INSTALLED_APPS = [
    'vault.apps.VaultConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'taggit',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'drf_spectacular',
    'corsheaders',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # WhiteNoise must come directly after SecurityMiddleware to serve static/root files.
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vault1337.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'frontend', 'dist'),  # React build output
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vault1337.wsgi.application'


# -------------------- DATABASE --------------------
# Set DATABASE_URL in .env for PostgreSQL in production:
#   DATABASE_URL=postgres://user:password@host:5432/dbname
# Falls back to SQLite for local development.

_db_url = os.getenv('DATABASE_URL', '')

if _db_url:
    import urllib.parse as _up
    _p = _up.urlparse(_db_url)
    _scheme = _p.scheme.split('+')[0]  # handle postgres+psycopg2 style
    _ENGINE_MAP = {
        'postgres': 'django.db.backends.postgresql',
        'postgresql': 'django.db.backends.postgresql',
        'mysql': 'django.db.backends.mysql',
        'sqlite': 'django.db.backends.sqlite3',
    }
    DATABASES = {
        'default': {
            'ENGINE': _ENGINE_MAP.get(_scheme, 'django.db.backends.postgresql'),
            'NAME': _p.path.lstrip('/'),
            'USER': _p.username or '',
            'PASSWORD': _p.password or '',
            'HOST': _p.hostname or 'localhost',
            'PORT': str(_p.port or 5432),
            # Keep connections alive between requests to avoid per-request TCP
            # handshake overhead. Set CONN_MAX_AGE=0 in .env to disable.
            'CONN_MAX_AGE': int(os.getenv('CONN_MAX_AGE', '60')),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# -------------------- AUTH --------------------

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# -------------------- INTERNATIONALISATION --------------------

LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

TAGGIT_CASE_INSENSITIVE = True


# -------------------- REACT FRONTEND --------------------

REACT_DIST_DIR = os.path.join(BASE_DIR, 'frontend', 'dist')


# -------------------- STATIC FILES --------------------
# STATIC_URL   — URL prefix used in templates and by the dev server
# STATIC_ROOT  — where collectstatic writes files for production (must differ
#                from any STATICFILES_DIRS entry to avoid collectstatic errors)
# STATICFILES_DIRS — extra locations the staticfiles finder searches

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# React assets are served by WhiteNoise via WHITENOISE_ROOT — no need to run
# them through collectstatic, so STATICFILES_DIRS is intentionally empty.
STATICFILES_DIRS = []

# WhiteNoise serves the React dist directory at the root URL (/, /assets/, …).
# Falls through to Django URL routing for paths not present on disk (SPA routes).
WHITENOISE_ROOT = REACT_DIST_DIR if os.path.isdir(REACT_DIST_DIR) else None

# Use WhiteNoise's compressed storage for Django's own static files (admin, etc.).
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

# -------------------- SAMPLE / YARA PATHS --------------------

SAMPLE_STORAGE_DIR = os.path.join(BASE_DIR, 'sample_storage')
YARA_RULES_DIR = os.path.join(BASE_DIR, 'vault', 'yara-rules')
# Backup destination for pg_dump output. Override with BACKUP_DIR env var to
# point at a mounted volume or network path in production.
BACKUP_DIR = os.getenv('BACKUP_DIR', os.path.join(BASE_DIR, 'backups'))

# Maximum file size for direct uploads (bytes). Default: 200 MB.
MAX_UPLOAD_SIZE_BYTES = int(os.getenv('MAX_UPLOAD_SIZE_MB', '200')) * 1024 * 1024

# -------------------- IOC ENRICHMENT --------------------
# VT: flag as true positive if malicious engine count >= this value (default 1).
IOC_VT_MALICIOUS_THRESHOLD = int(os.getenv('IOC_VT_MALICIOUS_THRESHOLD', '1'))
# AbuseIPDB: flag as true positive if abuse confidence score >= this value (default 25).
IOC_ABUSEIPDB_SCORE_THRESHOLD = int(os.getenv('IOC_ABUSEIPDB_SCORE_THRESHOLD', '25'))
# Seconds to sleep between VirusTotal calls (free tier: 4 req/min). Default 15.
IOC_ENRICH_VT_DELAY_SECONDS = int(os.getenv('IOC_ENRICH_VT_DELAY_SECONDS', '15'))
# OTX: flag as true positive if pulse count >= this value (default 1).
IOC_OTX_PULSE_THRESHOLD = int(os.getenv('IOC_OTX_PULSE_THRESHOLD', '1'))

# -------------------- LOGGING --------------------

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'vault': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# -------------------- DRF + JWT SETTINGS --------------------

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '30/minute',
        'user': '300/minute',
        'auth': '10/minute',  # applied to the token (login) endpoint only
    },
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
}


# -------------------- SSO SETTINGS --------------------
# All SSO settings are read from .env.  SSO is disabled by default — local
# username/password login always works regardless of SSO_ENABLED.

SSO_ENABLED = os.getenv('SSO_ENABLED', 'False') == 'True'
SSO_PROVIDER = os.getenv('SSO_PROVIDER', '')          # okta | azuread | google | oidc | github
SSO_CLIENT_ID = os.getenv('SSO_CLIENT_ID', '')
SSO_CLIENT_SECRET = os.getenv('SSO_CLIENT_SECRET', '')
SSO_TENANT_ID = os.getenv('SSO_TENANT_ID', '')        # Okta domain or Azure tenant ID
SSO_METADATA_URL = os.getenv('SSO_METADATA_URL', '')  # Generic OIDC discovery URL
SSO_AUTO_PROVISION = os.getenv('SSO_AUTO_PROVISION', 'True') == 'True'
SSO_DEFAULT_ROLE = os.getenv('SSO_DEFAULT_ROLE', 'Analyst')
SSO_ALLOW_LOCAL_LOGIN = os.getenv('SSO_ALLOW_LOCAL_LOGIN', 'True') == 'True'

_PROVIDER_BACKEND_MAP = {
    'okta':    'social_core.backends.okta.OktaOAuth2',
    'azuread': 'social_core.backends.azuread.AzureADOAuth2',
    'google':  'social_core.backends.google.GoogleOAuth2',
    'oidc':    'social_core.backends.open_id_connect.OpenIdConnectAuth',
    'github':  'social_core.backends.github.GithubOAuth2',
}

if SSO_ENABLED:
    try:
        import social_django  # noqa: F401  — verify the package is installed
        INSTALLED_APPS += ['social_django']
        MIDDLEWARE += ['social_django.middleware.SocialAuthExceptionMiddleware']
        TEMPLATES[0]['OPTIONS']['context_processors'] += [
            'social_django.context_processors.backends',
            'social_django.context_processors.login_redirect',
        ]

        AUTHENTICATION_BACKENDS = [
            'django.contrib.auth.backends.ModelBackend',
        ]
        if SSO_PROVIDER in _PROVIDER_BACKEND_MAP:
            AUTHENTICATION_BACKENDS.insert(0, _PROVIDER_BACKEND_MAP[SSO_PROVIDER])

        # PSA pipeline — conditionally include create_user step
        _pipeline = [
            'social_core.pipeline.social_auth.social_details',
            'social_core.pipeline.social_auth.social_uid',
            'social_core.pipeline.social_auth.auth_allowed',
            'social_core.pipeline.social_auth.social_user',
            'social_core.pipeline.user.get_username',
        ]
        if SSO_AUTO_PROVISION:
            _pipeline.append('social_core.pipeline.user.create_user')
        _pipeline += [
            'social_core.pipeline.social_auth.associate_user',
            'social_core.pipeline.social_auth.load_extra_data',
            'social_core.pipeline.user.user_details',
            'vault.sso.assign_default_role',
        ]
        SOCIAL_AUTH_PIPELINE = _pipeline

        SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/sso/complete/'
        SOCIAL_AUTH_LOGIN_ERROR_URL = '/sso/error/'
        SOCIAL_AUTH_URL_NAMESPACE = 'social'
        SOCIAL_AUTH_JSONFIELD_ENABLED = True

        # Okta OAuth2
        SOCIAL_AUTH_OKTA_OAUTH2_KEY = SSO_CLIENT_ID
        SOCIAL_AUTH_OKTA_OAUTH2_SECRET = SSO_CLIENT_SECRET
        if SSO_TENANT_ID:
            SOCIAL_AUTH_OKTA_OAUTH2_API_URL = f'https://{SSO_TENANT_ID}/oauth2/default'

        # Azure AD / Entra ID
        SOCIAL_AUTH_AZUREAD_OAUTH2_KEY = SSO_CLIENT_ID
        SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET = SSO_CLIENT_SECRET
        if SSO_TENANT_ID:
            SOCIAL_AUTH_AZUREAD_OAUTH2_TENANT_ID = SSO_TENANT_ID

        # Google Workspace
        SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = SSO_CLIENT_ID
        SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = SSO_CLIENT_SECRET

        # GitHub
        SOCIAL_AUTH_GITHUB_KEY = SSO_CLIENT_ID
        SOCIAL_AUTH_GITHUB_SECRET = SSO_CLIENT_SECRET

        # Generic OIDC
        SOCIAL_AUTH_OIDC_KEY = SSO_CLIENT_ID
        SOCIAL_AUTH_OIDC_SECRET = SSO_CLIENT_SECRET
        if SSO_METADATA_URL:
            SOCIAL_AUTH_OIDC_OIDC_ENDPOINT = SSO_METADATA_URL

    except ImportError:
        import warnings
        warnings.warn(
            'SSO_ENABLED=True but social-auth-app-django is not installed. '
            'Run: pip install social-auth-app-django',
            stacklevel=1,
        )
        SSO_ENABLED = False


# -------------------- CORS SETTINGS --------------------
# In .env set: CORS_ALLOWED_ORIGINS=http://localhost:5173,https://yourdomain.com
_cors_env = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173')
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_env.split(',') if o.strip()]
CORS_ALLOW_CREDENTIALS = True
