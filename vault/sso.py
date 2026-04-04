"""
SSO integration helpers for vault1337.

Bridges Python Social Auth (PSA) with djangorestframework-simplejwt so that
an OAuth/OIDC login ends with a JWT token pair that the React SPA can store.

Flow
────
1. Browser visits  /social/login/<provider>/          (PSA initiates OAuth)
2. Provider redirects to /social/complete/<provider>/ (PSA completes OAuth,
   calls our pipeline step, then calls django.contrib.auth.login())
3. PSA redirects to SOCIAL_AUTH_LOGIN_REDIRECT_URL = /sso/complete/
4. SSOCompleteView (vault/sso_views.py) reads request.user from the Django
   session, calls issue_sso_code(), and redirects the browser to the SPA at
   /sso-callback?code=<code>
5. The React SSOCallbackPage POSTs the code to /api/v1/auth/sso/exchange/
6. SSOExchangeView validates and returns the token pair; code is consumed
"""
import logging
import secrets

logger = logging.getLogger(__name__)

_SESSION_KEY = '_vault_sso_pending'
_CODE_TTL_SECONDS = 300  # 5 minutes to complete the exchange


def assign_default_role(backend, user, is_new=False, *args, **kwargs):
    """
    PSA pipeline step — assign SSO_DEFAULT_ROLE to newly provisioned users.

    Runs for every login but only takes action when ``is_new=True`` (first
    SSO login for this user).
    """
    if not is_new:
        return
    from django.conf import settings
    from django.contrib.auth.models import Group

    role_name = getattr(settings, 'SSO_DEFAULT_ROLE', 'Analyst')
    try:
        group = Group.objects.get(name=role_name)
        user.groups.add(group)
        logger.info('SSO: assigned role "%s" to new user "%s"', role_name, user.username)
    except Group.DoesNotExist:
        logger.warning(
            'SSO: default role "%s" not found — user "%s" provisioned without a role',
            role_name,
            user.username,
        )


def issue_sso_code(request, user):
    """
    Issue a JWT token pair for *user*, store it in the Django session under a
    random single-use exchange code, and return the code string.

    The session (and therefore the code) expires after ``_CODE_TTL_SECONDS``.
    The code is consumed and deleted by ``consume_sso_code()`` on first use.
    """
    from rest_framework_simplejwt.tokens import RefreshToken

    refresh = RefreshToken.for_user(user)
    code = secrets.token_urlsafe(32)
    request.session[_SESSION_KEY] = {
        'code': code,
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }
    request.session.set_expiry(_CODE_TTL_SECONDS)
    return code


def consume_sso_code(request, code):
    """
    Validate *code* against the Django session, delete the session key, and
    return ``(access_token, refresh_token)`` on success, or ``None`` if the
    code is invalid, expired, or has already been used.
    """
    pending = request.session.get(_SESSION_KEY)
    if not pending:
        return None
    stored_code = pending.get('code', '')
    # Use a constant-time comparison to avoid timing oracle on the code value.
    if not secrets.compare_digest(stored_code, code):
        return None
    del request.session[_SESSION_KEY]
    return pending['access'], pending['refresh']
