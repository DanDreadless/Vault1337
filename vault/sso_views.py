"""
Django views for the SSO OAuth callback redirect path.

These are plain Django Views (not DRF APIViews) because Python Social Auth
populates request.user via Django's session-based auth.login() — the JWT
authentication class used by DRF would not see that user.

URL:  /sso/complete/  →  SSOCompleteView
      /sso/error/     →  SSOErrorView
"""
import logging
from urllib.parse import urlencode

from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from django.views import View

from vault.sso import issue_sso_code

logger = logging.getLogger(__name__)


class SSOCompleteView(View):
    """
    GET /sso/complete/

    Called by PSA after a successful OAuth/OIDC flow.  request.user is set
    by PSA via django.contrib.auth.login().

    Issues a short-lived JWT exchange code, stores it in the session, and
    redirects the browser to the React SPA's /sso-callback route so the SPA
    can exchange the code for JWT tokens.
    """

    def get(self, request):
        user = request.user
        if not user.is_authenticated:
            logger.warning('SSOCompleteView reached with unauthenticated user')
            return redirect('/login?sso_error=not_authenticated')

        code = issue_sso_code(request, user)
        logger.info('SSO: issued exchange code for user "%s"', user.username)
        return redirect(f'/sso-callback?code={code}')


class SSOErrorView(View):
    """
    GET /sso/error/

    PSA redirects here on OAuth errors.  Passes the error message to the SPA
    login page as a query parameter so the user can see what went wrong.
    """

    def get(self, request):
        message = request.GET.get('message', 'SSO login failed.')
        logger.warning('SSO error: %s', message)
        params = urlencode({'sso_error': message})
        return redirect(f'/login?{params}')
