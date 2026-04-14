import gzip
import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse

import py7zr
import pyzipper
import requests
from django.conf import settings
from django.contrib.auth.models import Group, Permission as AuthPermission, User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.db import connection as db_connection
from django.db.models import Count, Q, Sum
from django.http import FileResponse, HttpResponse
from dotenv import load_dotenv, set_key
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ModelViewSet, ViewSet
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from vault.models import AnalysisResult, AuditLog, Comment, FailedLoginAttempt, File, IOC
from vault.utils import (
    fetch_vt_report,
    get_abuseipdb_data,
    get_api_key,
    get_file_path_from_sha256,
    get_passive_dns,
    get_shodan_data,
    get_spur_data,
    get_vt_data,
    get_vt_domain_data,
    get_whois_data,
    hash_sample,
    is_safe_url,
    run_sub_tool as _run_sub_tool,
    run_tool as _run_tool,
    validate_sha256,
)
from vault.workbench.attack_mapping import map_attack_techniques
from vault.workbench.stix_export import build_stix_bundle_for_file, build_stix_bundle_for_iocs
from vault.workbench.save_sample import SaveSample
from vault.workbench.simhash import hamming_distance, simhash_file

from vault.audit import log_action
from .permissions import IsStaffUser, vault_perm
from .serializers import (
    AnalysisResultSerializer,
    AuditLogSerializer,
    CommentSerializer,
    CreateUserAdminSerializer,
    FetchURLSerializer,
    FileDetailSerializer,
    FileSerializer,
    FileUploadSerializer,
    IOCSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    PermissionSerializer,
    RoleSerializer,
    SetPasswordSerializer,
    ToolRunSerializer,
    UserAdminSerializer,
    UserCreateSerializer,
    UserProfileSerializer,
)

logger = logging.getLogger(__name__)


# -------------------- THROTTLING --------------------

class AuthRateThrottle(AnonRateThrottle):
    """Stricter throttle scope applied only to the token (login) endpoint."""
    scope = 'auth'


class IOCEnrichThrottle(UserRateThrottle):
    scope = 'ioc_enrich'


class IntelIPThrottle(UserRateThrottle):
    scope = 'intel_ip'


class IntelDomainThrottle(UserRateThrottle):
    scope = 'intel_domain'


class VTEnrichThrottle(UserRateThrottle):
    scope = 'vt_enrich'


class MBLookupThrottle(UserRateThrottle):
    scope = 'mb_lookup'


class PasswordResetThrottle(AnonRateThrottle):
    """Strict throttle applied to both password-reset endpoints to prevent abuse."""
    scope = 'password_reset'


# -------------------- REFRESH COOKIE HELPERS --------------------

REFRESH_COOKIE_NAME = 'refresh_token'
REFRESH_COOKIE_PATH = '/api/v1/auth/'
REFRESH_COOKIE_AGE = 7 * 24 * 3600  # 7 days — matches SIMPLE_JWT REFRESH_TOKEN_LIFETIME


def _set_refresh_cookie(response, token_str: str) -> None:
    """Attach the refresh token as an httpOnly, SameSite=Strict cookie."""
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        token_str,
        max_age=REFRESH_COOKIE_AGE,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=not settings.DEBUG,
        samesite='Strict',
    )


def _clear_refresh_cookie(response) -> None:
    """Delete the refresh cookie."""
    response.delete_cookie(REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


_LOCKOUT_THRESHOLD = 10
_LOCKOUT_WINDOW_MINUTES = 15


def _get_client_ip(request):
    """Return the real client IP, respecting X-Forwarded-For if present."""
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _is_locked_out(username: str) -> bool:
    """Return True if username has >= _LOCKOUT_THRESHOLD failures in the last window."""
    from django.utils import timezone as _tz
    cutoff = _tz.now() - timedelta(minutes=_LOCKOUT_WINDOW_MINUTES)
    return (
        FailedLoginAttempt.objects
        .filter(username__iexact=username, timestamp__gte=cutoff)
        .count() >= _LOCKOUT_THRESHOLD
    )


class ThrottledTokenObtainPairView(TokenObtainPairView):
    """TokenObtainPairView with brute-force rate limiting, account lockout, and audit logging."""
    throttle_classes = [AuthRateThrottle]

    def post(self, request, *args, **kwargs):
        from django.utils import timezone as _tz
        attempted = request.data.get('username', '')
        ip = _get_client_ip(request)

        if _is_locked_out(attempted):
            log_action(request, 'login_failed', target_type='user',
                       detail={'attempted_username': attempted, 'reason': 'account_locked'})
            return Response(
                {'detail': 'Account temporarily locked due to too many failed login attempts. Try again in 15 minutes.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            # Successful login — clear failure history for this username
            FailedLoginAttempt.objects.filter(username__iexact=attempted).delete()
            log_action(request, 'login', target_type='user', target_id=attempted,
                       detail={'username': attempted})
        else:
            cutoff = _tz.now() - timedelta(minutes=_LOCKOUT_WINDOW_MINUTES)
            # Purge stale failures before recording the new one
            FailedLoginAttempt.objects.filter(username__iexact=attempted, timestamp__lt=cutoff).delete()
            FailedLoginAttempt.objects.create(username=attempted, ip_address=ip)
            log_action(request, 'login_failed', target_type='user',
                       detail={'attempted_username': attempted})

        return response


# -------------------- AUTH VIEWS --------------------

class LogoutView(APIView):
    """
    POST /api/v1/auth/logout/

    Blacklists the refresh token (read from the httpOnly cookie; falls back to
    the request body for compatibility) and clears the cookie.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get(REFRESH_COOKIE_NAME) or request.data.get('refresh')
        if not refresh_token:
            return Response(
                {'detail': 'refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        log_action(request, 'logout', target_type='user', target_id=request.user.username)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        _clear_refresh_cookie(response)
        return response


class SetRefreshCookieView(APIView):
    """
    POST /api/v1/auth/token/set-cookie/

    Accepts { "refresh": "<token>" } and stores it as an httpOnly cookie so
    the token is no longer held in localStorage.  Called immediately after
    login.  Returns 204.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        token_str = request.data.get('refresh', '')
        if not token_str:
            return Response({'detail': 'refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            RefreshToken(token_str)
        except TokenError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        _set_refresh_cookie(response, token_str)
        return response


class CookieTokenRefreshView(APIView):
    """
    POST /api/v1/auth/token/refresh/

    Reads the refresh token from the httpOnly cookie (no body required).
    Returns { "access": "<new-access-token>" } and rotates the cookie when
    ROTATE_REFRESH_TOKENS is True.  Returns 401 if the cookie is absent or invalid.
    """

    permission_classes = [AllowAny]
    throttle_classes = []

    def post(self, request):
        from rest_framework_simplejwt.settings import api_settings as jwt_settings
        token_str = request.COOKIES.get(REFRESH_COOKIE_NAME)
        if not token_str:
            return Response({'detail': 'No refresh cookie present.'}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            refresh = RefreshToken(token_str)
            access_str = str(refresh.access_token)

            response = Response({'access': access_str})

            if jwt_settings.ROTATE_REFRESH_TOKENS:
                if jwt_settings.BLACKLIST_AFTER_ROTATION:
                    try:
                        refresh.blacklist()
                    except AttributeError:
                        pass
                refresh.set_jti()
                refresh.set_exp()
                refresh.set_iat()
                _set_refresh_cookie(response, str(refresh))

            return response
        except TokenError as e:
            response = Response({'detail': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
            _clear_refresh_cookie(response)
            return response


class RegisterView(CreateAPIView):
    """
    POST /api/v1/auth/register/

    Public endpoint — creates a new user account.
    Returns the new user's id and username (no password fields).
    """

    queryset = File.objects.none()
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]

    def get_serializer(self, *args, **kwargs):
        kwargs.setdefault('context', self.get_serializer_context())
        return UserCreateSerializer(*args, **kwargs)


class PasswordResetRequestView(APIView):
    """
    POST /api/v1/auth/password-reset/

    Public endpoint.  Accepts { "email": "..." } and sends a time-limited
    reset link to that address if it belongs to an active account.  Always
    returns HTTP 200 regardless of whether the email is registered, to prevent
    email enumeration.
    """

    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):
        # Check live env so an admin can toggle this at runtime without restart.
        email_host_configured = bool(os.getenv('EMAIL_HOST', '').strip())
        raw_enabled = os.getenv('PASSWORD_RESET_ENABLED')
        if raw_enabled is not None:
            reset_enabled = raw_enabled.strip().lower() == 'true'
        else:
            reset_enabled = email_host_configured
        if not reset_enabled:
            return Response(
                {'detail': 'Password reset is not available. Contact your administrator.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        _RESET_RESPONSE = {'detail': 'If that email is registered, a reset link has been sent.'}

        try:
            user = User.objects.get(email__iexact=email, is_active=True)
        except User.DoesNotExist:
            return Response(_RESET_RESPONSE)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173').rstrip('/')
        reset_url = f"{frontend_url}/reset-password?uid={uid}&token={token}"

        send_mail(
            subject='Vault1337 — Password Reset',
            message=(
                f"You requested a password reset for your Vault1337 account.\n\n"
                f"Reset your password here:\n{reset_url}\n\n"
                f"This link expires in 3 days. If you did not request this, ignore this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True,
        )

        log_action(request, 'password_reset_request', target_type='user', target_id=email)
        return Response(_RESET_RESPONSE)


class PasswordResetConfirmView(APIView):
    """
    POST /api/v1/auth/password-reset/confirm/

    Public endpoint.  Accepts { "uid", "token", "new_password" }.
    Verifies the token and sets the new password.  Returns 400 if the token
    is invalid or expired.
    """

    permission_classes = [AllowAny]
    throttle_classes = [PasswordResetThrottle]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            pk = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=pk, is_active=True)
        except (ValueError, OverflowError, User.DoesNotExist):
            return Response({'detail': 'Invalid or expired reset link.'}, status=status.HTTP_400_BAD_REQUEST)

        if not default_token_generator.check_token(user, token):
            return Response({'detail': 'Invalid or expired reset link.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password, user)
        except DjangoValidationError as exc:
            return Response({'new_password': list(exc.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=['password'])

        log_action(request, 'password_reset_confirm', target_type='user', target_id=user.username)
        return Response({'detail': 'Password has been reset. You can now log in.'})


class UserDetailView(RetrieveUpdateAPIView):
    """
    GET  /api/v1/auth/user/ — return the authenticated user's profile.
    PATCH /api/v1/auth/user/ — update email or profile fields.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class FileViewSet(ModelViewSet):
    """
    ViewSet for File objects.

    list:   GET  /api/v1/files/
    create: POST /api/v1/files/
    retrieve: GET  /api/v1/files/{id}/
    destroy:  DELETE /api/v1/files/{id}/

    Extra actions:
      download   GET  /api/v1/files/{id}/download/
      run_tool   POST /api/v1/files/{id}/run_tool/
      add_tag    POST /api/v1/files/{id}/add_tag/
      remove_tag POST /api/v1/files/{id}/remove_tag/
      fetch_url  POST /api/v1/files/fetch_url/
    """

    http_method_names = ['get', 'post', 'delete', 'head', 'options']
    lookup_field = 'sha256'
    lookup_value_regex = '[a-fA-F0-9]{64}'

    # Permission map: action name → vault codename.
    # The 'comments' action is split by HTTP method in get_permissions().
    _PERM_MAP = {
        # Read — use Django's auto-generated view_file permission
        'list':             'view_file',
        'retrieve':         'view_file',
        'report':           'view_file',
        'analysis_results': 'view_file',
        'vt_behaviour':     'view_file',
        'similar':          'view_file',
        # Write / actions
        'create':           'upload_sample',
        'fetch_url':        'upload_sample',
        'destroy':          'delete_file',   # Django auto-generated
        'download':         'download_sample',
        'run_tool':         'run_tools',
        'map_attack':       'run_tools',
        'add_tag':          'manage_tags',
        'remove_tag':       'manage_tags',
        'vt_enrich':        'vt_enrich',
        'mb_lookup':        'mb_lookup',
        'stix_export':      'export_stix',
    }

    def get_permissions(self):
        action = self.action
        # comments: GET → view_file (Django auto); POST → add_comment (Django auto)
        if action == 'comments':
            codename = 'add_comment' if self.request.method == 'POST' else 'view_file'
            return [IsAuthenticated(), vault_perm(codename)()]
        codename = self._PERM_MAP.get(action)
        if codename:
            return [IsAuthenticated(), vault_perm(codename)()]
        return [IsAuthenticated()]

    # Magic byte prefixes (first 2 bytes, 4 hex chars) per file type category.
    # Mirrors detectFileCategories() in the frontend.
    _OFFICE_EXTS = ('.docx', '.xlsx', '.pptx', '.odt')
    _SCRIPT_EXTS = ('.py', '.js', '.ps1', '.sh', '.bat', '.vbs', '.rb', '.php', '.lua')

    def _apply_file_type(self, queryset, file_type):
        """Filter queryset by file type category."""
        if file_type == 'windows':
            return queryset.filter(magic__in=['4d5a'])
        if file_type == 'linux':
            return queryset.filter(magic__in=['7f45'])
        if file_type == 'macos':
            return queryset.filter(magic__in=['cefa', 'cffa', 'cafe'])
        if file_type == 'document':
            # PDF (2550), OLE/Office (d0cf), and ZIP-based Office formats
            office_zip = Q(magic='504b')
            for ext in self._OFFICE_EXTS:
                office_zip &= ~Q(name__iendswith=ext)
            office_zip = Q(magic='504b') & (
                Q(name__iendswith='.docx') | Q(name__iendswith='.xlsx') |
                Q(name__iendswith='.pptx') | Q(name__iendswith='.odt')
            )
            return queryset.filter(Q(magic__in=['2550', 'd0cf']) | office_zip)
        if file_type == 'archive':
            # ZIP (504b), 7-Zip (377a), gzip (1f8b), RAR (5261)
            # Exclude ZIP-based Office formats from this bucket
            qs = queryset.filter(magic__in=['504b', '377a', '1f8b', '5261'])
            for ext in self._OFFICE_EXTS:
                qs = qs.exclude(name__iendswith=ext)
            return qs
        if file_type == 'email':
            q = Q(mime='message/rfc822') | Q(name__iendswith='.eml') | Q(name__iendswith='.msg')
            return queryset.filter(q)
        if file_type == 'script':
            q = Q(mime__startswith='text/')
            for ext in self._SCRIPT_EXTS:
                q |= Q(name__iendswith=ext)
            return queryset.filter(q).exclude(tag__name='URL')
        if file_type == 'image':
            return queryset.filter(mime__startswith='image/')
        if file_type == 'url':
            return queryset.filter(tag__name='URL')
        return queryset

    def get_queryset(self):
        queryset = File.objects.all()
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(tag__name__icontains=search)
            ).distinct()
        file_type = self.request.query_params.get('file_type')
        if file_type:
            queryset = self._apply_file_type(queryset, file_type)
        return queryset

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return FileDetailSerializer
        if self.action == 'create':
            return FileUploadSerializer
        return FileSerializer

    def create(self, request, *args, **kwargs):
        """POST /api/v1/files/ — upload a new sample."""
        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        file = serializer.validated_data['file']
        tags = serializer.validated_data.get('tags', '')
        unzip = 'on' if serializer.validated_data.get('unzip', False) else ''
        password = serializer.validated_data.get('password', '') or None

        save_file = SaveSample(file, tags, unzip, password, request.user)
        result = save_file.save_file_and_update_model()

        if result == 'File already exists':
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        if not isinstance(result, tuple) or result[0] != 'success':
            return Response({'detail': str(result)}, status=status.HTTP_400_BAD_REQUEST)

        sha256 = result[1]
        try:
            instance = File.objects.get(sha256=sha256)
        except File.DoesNotExist:
            return Response(
                {'detail': 'File not found after upload.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        vt_result = fetch_vt_report(instance.sha256)
        if vt_result is not None:
            instance.vt_data = vt_result
            instance.save(update_fields=['vt_data'])
            threat_label = (vt_result.get('popular_threat_classification') or {}).get('suggested_threat_label', '')
            if threat_label:
                instance.tag.add(threat_label.lower())

        log_action(request, 'file_upload', target_type='file', target_id=instance.sha256,
                   detail={'name': instance.name, 'size': instance.size, 'mime': instance.mime})
        out_serializer = FileSerializer(instance, context={'request': request})
        return Response(out_serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        """DELETE /api/v1/files/{id}/ — delete a sample and its file on disk."""
        instance = self.get_object()

        try:
            clean_sha256 = validate_sha256(str(instance.sha256))
        except ValueError:
            return Response({'detail': 'Invalid SHA256 hash.'}, status=status.HTTP_400_BAD_REQUEST)

        file_path = os.path.join(settings.SAMPLE_STORAGE_DIR, clean_sha256)
        if os.path.exists(file_path):
            os.remove(file_path)

        log_action(request, 'file_delete', target_type='file', target_id=instance.sha256,
                   detail={'name': instance.name})
        tags_to_check = list(instance.tag.all())
        instance.tag.clear()
        instance.delete()
        for tag in tags_to_check:
            if not tag.taggit_taggeditem_items.exists():
                tag.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['get'])
    def download(self, request, sha256=None):
        """GET /api/v1/files/{id}/download/ — download sample as password-protected 7z."""
        file_instance = self.get_object()
        storage_location = settings.SAMPLE_STORAGE_DIR
        original_file_path = os.path.join(storage_location, file_instance.sha256)

        if not os.path.exists(original_file_path):
            return Response({'detail': 'File not found on disk.'}, status=status.HTTP_404_NOT_FOUND)

        tmp = tempfile.NamedTemporaryFile(suffix='.7z', delete=False)
        tmp_path = tmp.name
        tmp.close()

        try:
            with py7zr.SevenZipFile(tmp_path, 'w', password='infected') as zf:
                zf.write(original_file_path, arcname=file_instance.sha256)

            f = open(tmp_path, 'rb')
            response = FileResponse(
                f,
                as_attachment=True,
                filename=f'{file_instance.sha256}.7z',
                content_type='application/x-7z-compressed',
            )
            response._resource_closers.append(lambda p=tmp_path: os.unlink(p))
            log_action(request, 'file_download', target_type='file',
                       target_id=file_instance.sha256, detail={'name': file_instance.name})
            return response
        except Exception as e:
            os.unlink(tmp_path)
            logger.error("Error creating 7z archive for file %s: %s", file_instance.sha256, e)
            return Response(
                {'detail': f'Error creating archive: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=['post'])
    def run_tool(self, request, sha256=None):
        """POST /api/v1/files/{id}/run_tool/ — run an analysis tool against a sample."""
        file_instance = self.get_object()

        serializer = ToolRunSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tool = serializer.validated_data['tool']
        sub_tool = serializer.validated_data.get('sub_tool', '')
        password = serializer.validated_data.get('password', '') or None

        file_path = get_file_path_from_sha256(file_instance.sha256)
        if not file_path:
            return Response({'detail': 'File not found on disk.'}, status=status.HTTP_404_NOT_FOUND)

        if sub_tool:
            output = _run_sub_tool(tool, sub_tool, file_path)
        else:
            output = _run_tool(tool, file_path, password, request.user)

        # zip_extractor returns a dict {text, files} instead of a plain string
        if tool == 'zip_extractor' and isinstance(output, dict):
            return Response({
                'tool': tool,
                'sub_tool': sub_tool,
                'output': output['text'],
                'extracted_files': output['files'],
            })

        if output.endswith("' not supported."):
            return Response({'detail': output}, status=status.HTTP_400_BAD_REQUEST)

        # Persist the result so analysts can retrieve it later without re-running.
        AnalysisResult.objects.create(
            file=file_instance,
            tool=tool,
            sub_tool=sub_tool or '',
            output=output,
            ran_by=request.user,
        )

        response_data = {'tool': tool, 'sub_tool': sub_tool, 'output': output}

        # For extract-ioc, include the saved IOCs so the frontend doesn't
        # need a second round-trip to refresh the detail view.
        if tool == 'extract-ioc':
            response_data['iocs'] = IOCSerializer(
                file_instance.iocs.all(), many=True
            ).data

        return Response(response_data)

    @action(detail=True, methods=['post'])
    def add_tag(self, request, sha256=None):
        """POST /api/v1/files/{id}/add_tag/ — add a tag to a file."""
        file_instance = self.get_object()
        tag_name = request.data.get('tag')
        if not tag_name:
            return Response({'detail': 'No tag provided.'}, status=status.HTTP_400_BAD_REQUEST)

        file_instance.tag.add(tag_name.lower())
        log_action(request, 'tag_add', target_type='file', target_id=file_instance.sha256,
                   detail={'tag': tag_name.lower()})
        tags = list(file_instance.tag.values_list('name', flat=True))
        return Response({'tags': tags})

    @action(detail=True, methods=['post'])
    def remove_tag(self, request, sha256=None):
        """POST /api/v1/files/{id}/remove_tag/ — remove a tag from a file."""
        file_instance = self.get_object()
        tag_name = request.data.get('tag')
        if not tag_name:
            return Response({'detail': 'No tag provided.'}, status=status.HTTP_400_BAD_REQUEST)

        if tag_name not in file_instance.tag.values_list('name', flat=True):
            return Response(
                {'detail': f'Tag "{tag_name}" not found on this file.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        file_instance.tag.remove(tag_name)
        file_instance.save()
        log_action(request, 'tag_remove', target_type='file', target_id=file_instance.sha256,
                   detail={'tag': tag_name})
        tags = list(file_instance.tag.values_list('name', flat=True))
        return Response({'tags': tags})

    @action(detail=True, methods=['get', 'post'])
    def comments(self, request, sha256=None):
        """
        GET  /api/v1/files/{id}/comments/ — list comments for a file.
        POST /api/v1/files/{id}/comments/ — add a comment to a file.
        """
        file_instance = self.get_object()

        if request.method == 'GET':
            qs = Comment.objects.filter(file=file_instance)
            return Response(CommentSerializer(qs, many=True).data)

        serializer = CommentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(file=file_instance, author=request.user)
        log_action(request, 'comment_add', target_type='file', target_id=file_instance.sha256,
                   detail={'title': serializer.validated_data.get('title', ''),
                           'type': serializer.validated_data.get('comment_type', '')})
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'], url_path='vt-enrich',
            throttle_classes=[VTEnrichThrottle])
    def vt_enrich(self, request, sha256=None):
        """POST /api/v1/files/{id}/vt-enrich/ — fetch or refresh VT report for a sample."""
        file_obj = self.get_object()
        result = fetch_vt_report(file_obj.sha256)
        if result is None:
            return Response(
                {'detail': 'VT lookup failed or no API key configured.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        file_obj.vt_data = result
        file_obj.save(update_fields=['vt_data'])
        threat_label = (result.get('popular_threat_classification') or {}).get('suggested_threat_label', '')
        if threat_label:
            file_obj.tag.add(threat_label.lower())
        log_action(request, 'vt_enrich', target_type='file', target_id=file_obj.sha256)
        return Response({'vt_data': result})

    @action(detail=True, methods=['post'], url_path='mb-lookup',
            throttle_classes=[MBLookupThrottle])
    def mb_lookup(self, request, sha256=None):
        """
        POST /api/v1/files/{id}/mb-lookup/

        Queries MalwareBazaar for the sample's SHA256 and stores the result
        in File.mb_data. Returns the stored data on success.
        """
        file_obj = self.get_object()
        mbkey = get_api_key('MALWARE_BAZAAR_KEY')
        if not mbkey or mbkey == 'paste_your_api_key_here':
            return Response(
                {'detail': 'MALWARE_BAZAAR_KEY is not configured.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        try:
            resp = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data={'query': 'get_info', 'hash': file_obj.sha256},
                headers={'API-KEY': mbkey},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.warning('MB lookup failed for %s: %s', file_obj.sha256, exc)
            return Response(
                {'detail': 'MalwareBazaar request failed.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        query_status = data.get('query_status', '')
        if query_status == 'hash_not_found':
            return Response(
                {'detail': 'Hash not found in MalwareBazaar.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        if query_status != 'ok':
            return Response(
                {'detail': f'MalwareBazaar returned: {query_status}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        sample_data = (data.get('data') or [None])[0]
        if not sample_data:
            return Response(
                {'detail': 'No sample data in MalwareBazaar response.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        file_obj.mb_data = sample_data
        file_obj.save(update_fields=['mb_data'])
        log_action(request, 'mb_lookup', target_type='file', target_id=file_obj.sha256)
        return Response({'mb_data': sample_data})

    @action(detail=True, methods=['get'])
    def report(self, request, sha256=None):
        """
        GET /api/v1/files/{id}/report/

        Returns a structured JSON report aggregating all stored analysis data for
        the sample: hashes, file metadata, tags, VirusTotal summary, and IOCs.
        No new analysis is run — data is drawn exclusively from the database.
        """
        file_instance = self.get_object()

        # VirusTotal summary (from stored vt_data JSONField)
        vt_summary = None
        if file_instance.vt_data:
            vt = file_instance.vt_data
            stats = vt.get('last_analysis_stats', {})
            classification = (vt.get('popular_threat_classification') or {})
            vt_summary = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'threat_label': classification.get('suggested_threat_label', ''),
                'threat_category': classification.get('popular_threat_category', []),
                'scan_date': vt.get('last_analysis_date'),
                'reputation': vt.get('reputation', 0),
                'names': vt.get('names', [])[:10],
            }

        # IOCs grouped by type (confirmed true only)
        iocs_by_type: dict = {}
        for ioc in file_instance.iocs.filter(true_or_false=True).order_by('type', 'value'):
            iocs_by_type.setdefault(ioc.type, []).append(ioc.value)

        # Latest persisted tool result per (tool, sub_tool) combination.
        # We iterate results (already ordered -ran_at) and keep the first hit
        # per key, giving us a snapshot of the most recent analysis.
        tool_snapshot: dict = {}
        for ar in file_instance.analysis_results.all():
            key = f"{ar.tool}/{ar.sub_tool}" if ar.sub_tool else ar.tool
            if key not in tool_snapshot:
                tool_snapshot[key] = {
                    'tool': ar.tool,
                    'sub_tool': ar.sub_tool,
                    'output': ar.output,
                    'ran_at': ar.ran_at.isoformat(),
                    'ran_by': ar.ran_by.username if ar.ran_by else None,
                }

        report_data = {
            'file': {
                'id': file_instance.id,
                'name': file_instance.name,
                'size': file_instance.size,
                'magic': file_instance.magic,
                'mime': file_instance.mime,
                'created_date': file_instance.created_date.isoformat()
                    if file_instance.created_date else None,
                'uploaded_by': file_instance.uploaded_by.username
                    if file_instance.uploaded_by else None,
            },
            'hashes': {
                'md5':    file_instance.md5,
                'sha1':   file_instance.sha1,
                'sha256': file_instance.sha256,
                'sha512': file_instance.sha512,
            },
            'tags': sorted(file_instance.tag.values_list('name', flat=True)),
            'vt': vt_summary,
            'iocs': iocs_by_type,
            'ioc_count': sum(len(v) for v in iocs_by_type.values()),
            'analysis': tool_snapshot,
        }
        return Response(report_data)

    @action(detail=True, methods=['get'])
    def analysis_results(self, request, sha256=None):
        """
        GET /api/v1/files/{id}/analysis_results/

        Returns all persisted tool run results for the sample, newest first.
        Optionally filter by tool: ?tool=pefile
        """
        file_instance = self.get_object()
        qs = file_instance.analysis_results.all()
        tool_filter = request.query_params.get('tool', '').strip()
        if tool_filter:
            qs = qs.filter(tool=tool_filter)
        return Response(AnalysisResultSerializer(qs, many=True).data)

    @action(detail=True, methods=['get'])
    def vt_behaviour(self, request, sha256=None):
        """
        GET /api/v1/files/{id}/vt_behaviour/

        Fetches the VirusTotal sandbox behaviour report for the sample.
        Requires a VT API key with behaviour access (premium/enterprise).
        Returns the raw VT behaviour JSON on success.
        """
        file_instance = self.get_object()
        vt_key = get_api_key('VT_KEY')
        if not vt_key:
            return Response(
                {'detail': 'VT_KEY is not configured.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        url = f'https://www.virustotal.com/api/v3/files/{file_instance.sha256}/behaviours'
        try:
            resp = requests.get(
                url,
                headers={'x-apikey': vt_key},
                timeout=30,
            )
        except requests.RequestException as exc:
            logger.warning('VT behaviour request failed for %s: %s', file_instance.sha256, exc)
            return Response(
                {'detail': 'Request to VirusTotal failed.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if resp.status_code == 404:
            return Response(
                {'detail': 'No behaviour report found on VirusTotal for this sample.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        if resp.status_code == 403:
            return Response(
                {'detail': 'VT API key lacks access to behaviour reports (premium/enterprise required).'},
                status=status.HTTP_403_FORBIDDEN,
            )
        if not resp.ok:
            return Response(
                {'detail': f'VirusTotal returned status {resp.status_code}.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response(resp.json())

    @action(detail=True, methods=['post'], url_path='map-attack')
    def map_attack(self, request, sha256=None):
        """
        POST /api/v1/files/{id}/map-attack/

        Scans all saved AnalysisResult outputs for this sample and maps them
        to MITRE ATT&CK techniques. Saves results to File.attack_mapping and
        returns the list of matched techniques.
        """
        file_instance = self.get_object()
        techniques = map_attack_techniques(file_instance)
        file_instance.attack_mapping = techniques
        file_instance.save(update_fields=['attack_mapping'])
        return Response({'techniques': techniques})

    @action(detail=True, methods=['get'], url_path='stix')
    def stix_export(self, request, sha256=None):
        """
        GET /api/v1/files/{id}/stix/

        Returns a STIX 2.1 bundle JSON file containing the sample's file
        observable, a hash indicator, and all associated IOCs.
        """
        file_instance = self.get_object()
        try:
            bundle_json = build_stix_bundle_for_file(file_instance)
        except Exception as exc:
            logger.error('STIX export failed for file %d: %s', file_instance.pk, exc)
            return Response({'detail': 'STIX export failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        filename = f'vault1337_{file_instance.sha256[:12]}.stix.json'
        log_action(request, 'stix_export', target_type='file', target_id=file_instance.sha256)
        return HttpResponse(
            bundle_json,
            content_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'},
        )

    @action(detail=True, methods=['get'])
    def similar(self, request, sha256=None):
        """
        GET /api/v1/files/{id}/similar/?threshold=10

        Returns all samples whose SimHash Hamming distance from this sample
        is <= threshold (default 10, max 32), sorted by distance ascending.
        Files without a SimHash (uploaded before the feature was added) are
        excluded.  The queried file itself is never included in results.
        """
        file_instance = self.get_object()

        if file_instance.simhash is None:
            return Response(
                {'detail': 'No SimHash available for this file. Re-upload to generate one.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        try:
            threshold = int(request.query_params.get('threshold', 10))
        except (ValueError, TypeError):
            threshold = 10
        threshold = max(0, min(threshold, 32))

        target = file_instance.simhash
        candidates = (
            File.objects
            .exclude(pk=file_instance.pk)
            .exclude(simhash=None)
            .values('id', 'name', 'sha256', 'mime', 'size', 'simhash', 'created_date')
        )

        results = []
        for c in candidates:
            dist = hamming_distance(target, c['simhash'])
            if dist <= threshold:
                results.append({
                    'id':           c['id'],
                    'name':         c['name'],
                    'sha256':       c['sha256'],
                    'mime':         c['mime'],
                    'size':         c['size'],
                    'distance':     dist,
                    'created_date': c['created_date'].isoformat() if c['created_date'] else None,
                })

        results.sort(key=lambda x: x['distance'])
        return Response({'threshold': threshold, 'results': results})

    @action(detail=False, methods=['post'])
    def fetch_url(self, request):
        """POST /api/v1/files/fetch_url/ — fetch a URL and store the response as a sample."""
        serializer = FetchURLSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        url = serializer.validated_data['url']
        tags_str = serializer.validated_data.get('tags', '')
        tags = tags_str.split(',') if tags_str else []
        tags.append('url')

        if not is_safe_url(url):
            return Response(
                {'detail': 'Invalid or disallowed URL.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Re-resolve the hostname immediately before connecting and re-validate
        # the resulting IP.  This collapses the DNS-rebinding window: between
        # is_safe_url() and requests.get() a malicious DNS server could return
        # a different (internal) IP.  By resolving here and substituting the IP
        # directly into the URL we ensure requests.get() never triggers a second
        # DNS lookup.
        try:
            _parsed = urlparse(url)
            _hostname = _parsed.hostname
            _resolved_ip = socket.gethostbyname(_hostname)
            _addr = ipaddress.ip_address(_resolved_ip)
            if (_addr.is_private or _addr.is_loopback or _addr.is_link_local
                    or _addr.is_reserved or _addr.is_multicast):
                return Response(
                    {'detail': 'Invalid or disallowed URL.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception:
            return Response(
                {'detail': 'Invalid or disallowed URL.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Build the fetch URL using the pre-resolved IP so no further DNS lookup
        # occurs.  For HTTP: swap hostname for IP, set Host header.  For HTTPS:
        # we must keep the hostname in the URL so TLS certificate verification
        # uses the correct SNI; the IP is still pinned via the Host header and
        # the second validation above has already confirmed it is safe.
        if _parsed.scheme == 'http':
            _netloc = _resolved_ip if not _parsed.port else f'{_resolved_ip}:{_parsed.port}'
            _safe_fetch_url = urlunparse(_parsed._replace(netloc=_netloc))
            _req_headers = {'Host': _hostname}
        else:
            _safe_fetch_url = urlunparse(_parsed)
            _req_headers = {}

        try:
            resp = requests.get(
                _safe_fetch_url,
                headers=_req_headers,
                stream=True,
                timeout=5,
                allow_redirects=False,
            )
        except Exception as e:
            logger.error("Error fetching URL %s: %s", url, e)
            return Response({'detail': 'Error fetching URL.'}, status=status.HTTP_400_BAD_REQUEST)

        if resp.status_code != 200:
            return Response(
                {'detail': f'Remote server returned {resp.status_code}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        samples_dir = settings.SAMPLE_STORAGE_DIR
        filename = ''
        content_type_header = resp.headers.get('Content-Type', 'application/octet-stream')

        real_samples_dir = os.path.realpath(samples_dir)

        if 'Content-Disposition' in resp.headers:
            content_disposition = resp.headers['Content-Disposition']
            if 'filename' in content_disposition:
                filename = content_disposition.split('filename=')[1]
                filename_pattern = re.compile(r'[^a-zA-Z0-9-_]')
                safe_filename = filename_pattern.sub('', filename)
                if not safe_filename:
                    return Response(
                        {'detail': 'Error: Content-Disposition filename is empty after sanitisation.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                file_path = os.path.join(samples_dir, safe_filename)
                # Canonicalize; reassign so every downstream use (open, os.remove,
                # os.rename) operates on the validated real path, not the raw input.
                file_path = os.path.realpath(file_path)
                if not file_path.startswith(real_samples_dir + os.sep):
                    return Response(
                        {'detail': 'Error: unsafe filename in Content-Disposition.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                with open(file_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
        else:
            source_code = resp.text
            filename_pattern = re.compile(r'[^a-zA-Z0-9-_]')
            safe_filename = filename_pattern.sub('', url)
            if not safe_filename:
                return Response(
                    {'detail': 'Error: Invalid URL produces empty filename.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            file_path = os.path.join(samples_dir, f'webpage_{safe_filename}.html')
            # Canonicalize; reassign so every downstream use (open, os.remove,
            # os.rename) operates on the validated real path, not the raw input.
            file_path = os.path.realpath(file_path)
            if not file_path.startswith(real_samples_dir + os.sep):
                return Response(
                    {'detail': 'Error: unsafe URL produces invalid filename.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(source_code)

        md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(file_path)
        name = filename if filename else url
        if filename:
            mime = content_type_header

        if File.objects.filter(sha256=sha256).exists():
            os.remove(file_path)
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        final_path = os.path.join(samples_dir, sha256)
        os.rename(file_path, final_path)
        fingerprint, bytes_hashed = simhash_file(final_path)

        vault_item = File(
            name=name,
            size=size,
            magic=magic_byte,
            mime=mime,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            uploaded_by=request.user,
            simhash=fingerprint,
            simhash_input_size=bytes_hashed,
        )
        vault_item.save()
        for tag in tags:
            vault_item.tag.add(tag.strip().lower())
        vault_item.save()

        vt_result = fetch_vt_report(sha256)
        if vt_result is not None:
            vault_item.vt_data = vt_result
            vault_item.save(update_fields=['vt_data'])
            threat_label = (vt_result.get('popular_threat_classification') or {}).get('suggested_threat_label', '')
            if threat_label:
                vault_item.tag.add(threat_label.lower())

        log_action(request, 'file_fetch_url', target_type='file', target_id=sha256,
                   detail={'url': url, 'name': name, 'size': size})
        out_serializer = FileSerializer(vault_item, context={'request': request})
        return Response(out_serializer.data, status=status.HTTP_201_CREATED)


class IOCViewSet(mixins.ListModelMixin, mixins.UpdateModelMixin, GenericViewSet):
    """
    ViewSet for IOC indicators.

    list:   GET   /api/v1/iocs/
    update: PATCH /api/v1/iocs/{id}/
    enrich: POST  /api/v1/iocs/{id}/enrich/
    """

    serializer_class = IOCSerializer
    http_method_names = ['get', 'patch', 'post', 'head', 'options']

    _PERM_MAP = {
        'list':           'view_ioc',
        'retrieve':       'view_ioc',
        'samples':        'view_ioc',
        'partial_update': 'manage_iocs',
        'enrich':         'enrich_iocs',
        'bulk_delete':    'manage_iocs',
        'export_stix':    'export_stix',
    }

    def get_permissions(self):
        codename = self._PERM_MAP.get(self.action)
        if codename:
            return [IsAuthenticated(), vault_perm(codename)()]
        return [IsAuthenticated()]

    # Valid IOC types for the ?ioc_type= filter (whitelist prevents arbitrary
    # field injection into the ORM filter call).
    _VALID_TYPES = {
        'ip', 'domain', 'email', 'url', 'bitcoin', 'cve',
        'registry', 'named_pipe', 'win_persistence', 'scheduled_task',
        'linux_cron', 'systemd_unit', 'macos_launchagent',
    }

    def get_queryset(self):
        # Non-list actions need the full queryset so any IOC can be found by pk
        # regardless of its current true_or_false / type value.
        if self.action != 'list':
            return IOC.objects.all()

        filter_option = self.request.query_params.get('filter', 'true')
        search = self.request.query_params.get('search')
        ioc_type = self.request.query_params.get('ioc_type')

        if filter_option == 'false':
            queryset = IOC.objects.filter(true_or_false=False)
        elif filter_option == 'both':
            queryset = IOC.objects.all()
        else:
            queryset = IOC.objects.filter(true_or_false=True)

        if ioc_type and ioc_type in self._VALID_TYPES:
            queryset = queryset.filter(type=ioc_type)

        if search:
            queryset = queryset.filter(
                Q(value__icontains=search) | Q(files__name__icontains=search)
            ).distinct()

        return queryset.order_by('id')

    def partial_update(self, request, *args, **kwargs):
        """
        PATCH /api/v1/iocs/{id}/
        When the caller explicitly sets true_or_false, mark the IOC as
        manually overridden so background enrichment won't undo their choice.
        """
        if 'true_or_false' in request.data:
            ioc = self.get_object()
            ioc.manually_overridden = True
            ioc.save(update_fields=['manually_overridden'])
            log_action(request, 'ioc_override', target_type='ioc', target_id=ioc.value,
                       detail={'true_or_false': request.data['true_or_false']})
        return super().partial_update(request, *args, **kwargs)

    @action(detail=True, methods=['post'], url_path='enrich',
            throttle_classes=[IOCEnrichThrottle])
    def enrich(self, request, pk=None):
        """
        POST /api/v1/iocs/{id}/enrich/
        Re-run threat-intel enrichment for a single IP or domain IOC.
        Clears manually_overridden so the fresh enrichment result takes effect.
        Returns the updated IOC.  Only supported for ip and domain types.
        """
        from vault.workbench.ioc_enrichment import enrich_ioc
        ioc = self.get_object()
        if ioc.type not in ('ip', 'domain'):
            return Response(
                {'detail': 'Enrichment is only supported for ip and domain IOC types.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        enrich_ioc(ioc)
        ioc.refresh_from_db()
        log_action(request, 'ioc_enrich', target_type='ioc', target_id=ioc.value,
                   detail={'type': ioc.type})
        return Response(IOCSerializer(ioc).data)

    @action(detail=True, methods=['get'], url_path='samples')
    def samples(self, request, pk=None):
        """
        GET /api/v1/iocs/{id}/samples/

        Returns all files that share this IOC — enables pivoting on shared
        infrastructure across samples in the vault.
        """
        ioc = self.get_object()
        files = ioc.files.all().order_by('-created_date')
        return Response(FileSerializer(files, many=True).data)

    @action(detail=False, methods=['post'], url_path='bulk-delete')
    def bulk_delete(self, request):
        """
        POST /api/v1/iocs/bulk-delete/

        Body: {"ids": [1, 2, 3]}
        Deletes the specified IOCs. Requires manage_iocs permission.
        """
        ids = request.data.get('ids', [])
        if not isinstance(ids, list) or not ids:
            return Response({'detail': 'Provide a non-empty list of IOC ids.'}, status=status.HTTP_400_BAD_REQUEST)

        deleted_count, _ = IOC.objects.filter(pk__in=ids).delete()
        log_action(request, 'ioc_delete', target_type='ioc',
                   detail={'ids': ids, 'count': deleted_count})
        return Response({'deleted': deleted_count})

    @action(detail=False, methods=['post'], url_path='export-stix')
    def export_stix(self, request):
        """
        POST /api/v1/iocs/export-stix/

        Body: {"ids": [1, 2, 3]}
        Returns a STIX 2.1 bundle JSON file for the selected IOC IDs.
        The caller must own or have access to these IOCs (authenticated).
        """
        ids = request.data.get('ids', [])
        if not isinstance(ids, list) or not ids:
            return Response({'detail': 'Provide a non-empty list of IOC ids.'}, status=status.HTTP_400_BAD_REQUEST)

        iocs = IOC.objects.filter(pk__in=ids)
        if not iocs.exists():
            return Response({'detail': 'No matching IOCs found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            bundle_json = build_stix_bundle_for_iocs(iocs)
        except Exception as exc:
            logger.error('STIX export failed for IOC ids %s: %s', ids, exc)
            return Response({'detail': 'STIX export failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return HttpResponse(
            bundle_json,
            content_type='application/json',
            headers={'Content-Disposition': 'attachment; filename="vault1337_iocs.stix.json"'},
        )


# -------------------- YARA RULES --------------------

class YaraViewSet(ViewSet):
    """
    CRUD for YARA rule files on disk.

    list:    GET  /api/v1/yara/
    create:  POST /api/v1/yara/
    retrieve: GET  /api/v1/yara/{pk}/
    update:  PUT  /api/v1/yara/{pk}/
    destroy: DELETE /api/v1/yara/{pk}/

    Rules are stored as plain .yar files in settings.YARA_RULES_DIR.
    The {pk} lookup value is the rule filename without the .yar extension.
    """

    def get_permissions(self):
        if self.action in ('list', 'retrieve'):
            return [IsAuthenticated(), vault_perm('view_yara')()]
        if self.action in ('create', 'update', 'destroy'):
            return [IsAuthenticated(), vault_perm('manage_yara')()]
        return [IsAuthenticated()]

    def _rules_dir(self):
        return settings.YARA_RULES_DIR

    def _rule_path(self, name):
        """Return the absolute path for a rule given its bare name (no extension).

        Raises ValueError if the resolved path escapes the rules directory
        (e.g. via a symlink planted inside the directory).
        """
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
        path = os.path.join(self._rules_dir(), f'{safe_name}.yar')
        # Canonicalize: guard against symlink-based escape from the rules dir.
        rules_dir_real = os.path.realpath(self._rules_dir())
        if not os.path.realpath(path).startswith(rules_dir_real + os.sep):
            raise ValueError('Rule name resolves to a path outside the rules directory.')
        return path

    def list(self, request, *args, **kwargs):
        """Return a list of all .yar rule names and their content."""
        rules_dir = self._rules_dir()
        if not os.path.isdir(rules_dir):
            return Response([], status=status.HTTP_200_OK)

        rules = []
        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith('.yar'):
                continue
            full_path = os.path.join(rules_dir, fname)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='replace') as fh:
                    content = fh.read()
            except OSError as e:
                logger.warning("Could not read YARA rule %s: %s", fname, e)
                content = ''
            rules.append({'name': fname[:-4], 'filename': fname, 'content': content})

        return Response(rules)

    def retrieve(self, request, *args, **kwargs):
        """GET /api/v1/yara/{name}/ — return name + content of one rule."""
        name = kwargs.get('pk', '')
        try:
            rule_path = self._rule_path(name)
        except ValueError:
            return Response({'detail': 'Invalid rule name.'}, status=status.HTTP_400_BAD_REQUEST)
        if not os.path.isfile(rule_path):
            return Response({'detail': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        with open(rule_path, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read()

        return Response({'name': name, 'filename': f'{name}.yar', 'content': content})

    def create(self, request, *args, **kwargs):
        """POST /api/v1/yara/ — create a new .yar file. Body: {name, content}."""
        name = request.data.get('name', '').strip()
        content = request.data.get('content', '')

        if not name:
            return Response({'detail': 'name is required.'}, status=status.HTTP_400_BAD_REQUEST)

        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
        if not safe_name:
            return Response({'detail': 'Invalid rule name.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            rule_path = self._rule_path(safe_name)
        except ValueError:
            return Response({'detail': 'Invalid rule name.'}, status=status.HTTP_400_BAD_REQUEST)
        if os.path.isfile(rule_path):
            return Response(
                {'detail': f'Rule "{safe_name}" already exists.'},
                status=status.HTTP_409_CONFLICT,
            )

        os.makedirs(self._rules_dir(), exist_ok=True)
        with open(rule_path, 'w', encoding='utf-8') as fh:
            fh.write(content)

        log_action(request, 'yara_create', target_type='yara', target_id=safe_name)
        return Response(
            {'name': safe_name, 'filename': f'{safe_name}.yar', 'content': content},
            status=status.HTTP_201_CREATED,
        )

    def update(self, request, *args, **kwargs):
        """PUT /api/v1/yara/{name}/ — overwrite an existing rule's content."""
        name = kwargs.get('pk', '')
        try:
            rule_path = self._rule_path(name)
        except ValueError:
            return Response({'detail': 'Invalid rule name.'}, status=status.HTTP_400_BAD_REQUEST)

        if not os.path.isfile(rule_path):
            return Response({'detail': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        content = request.data.get('content', '')
        with open(rule_path, 'w', encoding='utf-8') as fh:
            fh.write(content)

        log_action(request, 'yara_update', target_type='yara', target_id=name)
        return Response({'name': name, 'filename': f'{name}.yar', 'content': content})

    def destroy(self, request, *args, **kwargs):
        """DELETE /api/v1/yara/{name}/ — delete a .yar file."""
        name = kwargs.get('pk', '')
        try:
            rule_path = self._rule_path(name)
        except ValueError:
            return Response({'detail': 'Invalid rule name.'}, status=status.HTTP_400_BAD_REQUEST)

        if not os.path.isfile(rule_path):
            return Response({'detail': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        log_action(request, 'yara_delete', target_type='yara', target_id=name)
        os.remove(rule_path)
        return Response(status=status.HTTP_204_NO_CONTENT)


# -------------------- IP INTELLIGENCE --------------------

class IPCheckView(APIView):
    """
    POST /api/v1/intel/ip/

    Body: { "ip": "1.2.3.4" }
    Returns aggregated data from AbuseIPDB, Spur, VirusTotal, and Shodan.
    """

    permission_classes = [IsAuthenticated, vault_perm('use_intel')]
    throttle_classes = [IntelIPThrottle]

    def post(self, request):
        ip = request.data.get('ip', '').strip()
        if not ip:
            return Response({'detail': 'ip is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return Response({'detail': 'Invalid IP address.'}, status=status.HTTP_400_BAD_REQUEST)

        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return Response(
                {'detail': 'Private, loopback, and reserved addresses cannot be queried.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({
            'ip': ip,
            'abuseipdb': get_abuseipdb_data(ip),
            'spur': get_spur_data(ip),
            'virustotal': get_vt_data(ip),
            'shodan': get_shodan_data(ip),
        })


# -------------------- DOMAIN INTELLIGENCE --------------------

_DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
    re.IGNORECASE,
)


class DomainCheckView(APIView):
    """
    POST /api/v1/intel/domain/

    Body: { "domain": "example.com" }
    Returns aggregated data from WHOIS, VirusTotal, and Passive DNS.
    """

    permission_classes = [IsAuthenticated, vault_perm('use_intel')]
    throttle_classes = [IntelDomainThrottle]

    def post(self, request):
        domain = request.data.get('domain', '').strip().lower()
        if not domain:
            return Response({'detail': 'domain is required.'}, status=status.HTTP_400_BAD_REQUEST)

        if not _DOMAIN_RE.match(domain):
            return Response({'detail': 'Invalid domain name.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'domain': domain,
            'whois': get_whois_data(domain),
            'virustotal': get_vt_domain_data(domain),
            'passive_dns': get_passive_dns(domain),
        })


# -------------------- USER & ROLE MANAGEMENT (staff only) --------------------

class UserManagementViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    GenericViewSet,
):
    """
    Staff-only CRUD for user accounts.

    list:     GET  /api/v1/admin/users/
    create:   POST /api/v1/admin/users/
    retrieve: GET  /api/v1/admin/users/{id}/
    update:   PATCH /api/v1/admin/users/{id}/
    destroy:  DELETE /api/v1/admin/users/{id}/
    set_password: POST /api/v1/admin/users/{id}/set_password/
    """

    permission_classes = [IsStaffUser]
    pagination_class = None
    http_method_names = ['get', 'post', 'patch', 'delete', 'head', 'options']

    def get_serializer_context(self):
        """Inject the Admin group into context so UserAdminSerializer can use it
        without issuing a per-user query when serialising a list."""
        ctx = super().get_serializer_context()
        ctx['admin_group'] = Group.objects.filter(name='Admin').first()
        return ctx

    def get_queryset(self):
        return (
            User.objects.all()
            .select_related('profile')
            .prefetch_related('groups__permissions')
            .order_by('id')
        )

    def get_serializer_class(self):
        if self.action == 'create':
            return CreateUserAdminSerializer
        if self.action == 'set_password':
            return SetPasswordSerializer
        return UserAdminSerializer

    def create(self, request, *args, **kwargs):
        """POST /api/v1/admin/users/ — create a new user account."""
        serializer = CreateUserAdminSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        log_action(request, 'user_create', target_type='user', target_id=user.username,
                   detail={'email': user.email, 'is_staff': user.is_staff})
        return Response(UserAdminSerializer(user).data, status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        """PATCH /api/v1/admin/users/{id}/ — update a user account."""
        user = self.get_object()
        response = super().partial_update(request, *args, **kwargs)
        if response.status_code < 300:
            log_action(request, 'user_update', target_type='user', target_id=user.username,
                       detail={k: v for k, v in request.data.items() if k != 'password'})
        return response

    def destroy(self, request, *args, **kwargs):
        """DELETE /api/v1/admin/users/{id}/ — delete a user account."""
        user = self.get_object()
        if user == request.user:
            return Response(
                {'detail': 'You cannot delete your own account.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        log_action(request, 'user_delete', target_type='user', target_id=user.username)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'], url_path='set_password')
    def set_password(self, request, pk=None):
        """POST /api/v1/admin/users/{id}/set_password/ — set a user's password."""
        user = self.get_object()
        serializer = SetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user.set_password(serializer.validated_data['password'])
        user.save()
        log_action(request, 'user_set_password', target_type='user', target_id=user.username)
        return Response({'detail': 'Password updated.'})


class RoleViewSet(ModelViewSet):
    """
    Staff-only CRUD for roles (Django Groups with vault permissions).

    list:     GET  /api/v1/admin/roles/
    create:   POST /api/v1/admin/roles/
    retrieve: GET  /api/v1/admin/roles/{id}/
    update:   PATCH /api/v1/admin/roles/{id}/
    destroy:  DELETE /api/v1/admin/roles/{id}/
    """

    permission_classes = [IsStaffUser]
    pagination_class = None
    serializer_class = RoleSerializer
    http_method_names = ['get', 'post', 'patch', 'delete', 'head', 'options']

    def get_queryset(self):
        return Group.objects.all().prefetch_related('permissions').order_by('id')

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        if response.status_code == 201:
            log_action(request, 'role_create', target_type='role',
                       target_id=response.data.get('name', ''))
        return response

    def partial_update(self, request, *args, **kwargs):
        role = self.get_object()
        response = super().partial_update(request, *args, **kwargs)
        if response.status_code < 300:
            log_action(request, 'role_update', target_type='role', target_id=role.name)
        return response

    def destroy(self, request, *args, **kwargs):
        role = self.get_object()
        log_action(request, 'role_delete', target_type='role', target_id=role.name)
        return super().destroy(request, *args, **kwargs)


class AvailablePermissionsView(APIView):
    """GET /api/v1/admin/permissions/ — list all assignable vault permissions."""

    permission_classes = [IsStaffUser]

    # Django auto-generated permissions we use directly instead of custom duplicates.
    # Stored as (content_type model, codename) pairs so the query is unambiguous.
    _AUTO_PERMS = [
        ('file',    'view_file'),    # replaces view_sample
        ('file',    'delete_file'),  # replaces delete_sample
        ('ioc',     'view_ioc'),     # replaces custom view_ioc on File
        ('comment', 'add_comment'),  # replaces add_comments
    ]

    def get(self, request):
        # Custom permissions live on the File content type.
        custom_codenames = [codename for codename, _ in File._meta.permissions]
        custom_q = Q(content_type__app_label='vault', content_type__model='file',
                     codename__in=custom_codenames)

        # Auto-generated permissions we expose alongside the custom ones.
        auto_q = Q()
        for model, codename in self._AUTO_PERMS:
            auto_q |= Q(content_type__app_label='vault',
                        content_type__model=model,
                        codename=codename)

        perms = AuthPermission.objects.filter(custom_q | auto_q).order_by('codename')
        return Response(PermissionSerializer(perms, many=True).data)


# -------------------- API KEY MANAGER --------------------

_ENV_PATH = os.path.join(settings.BASE_DIR, '.env')
_API_KEY_NAMES = ('VT_KEY', 'MALWARE_BAZAAR_KEY', 'ABUSEIPDB_KEY', 'SPUR_KEY', 'SHODAN_KEY', 'OTX_KEY')


class APIKeyView(APIView):
    """
    GET  /api/v1/admin/keys/ — return masked API key values (staff only).
    POST /api/v1/admin/keys/ — update a single key. Body: {key, value}.
    """

    permission_classes = [IsStaffUser]

    def _mask(self, value):
        """Show only the last 4 characters of a key."""
        if not value or value == 'paste_your_api_key_here':
            return '(not set)'
        return f'{"*" * (len(value) - 4)}{value[-4:]}' if len(value) > 4 else '****'

    def get(self, request):
        keys = {name: self._mask(get_api_key(name)) for name in _API_KEY_NAMES}
        return Response(keys)

    def post(self, request):
        key = request.data.get('key', '').strip()
        value = request.data.get('value', '').strip()

        if not key or not value:
            return Response(
                {'detail': 'Both key and value are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if key not in _API_KEY_NAMES:
            return Response(
                {'detail': f'Unknown key "{key}". Allowed: {", ".join(_API_KEY_NAMES)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        set_key(_ENV_PATH, key, value)
        load_dotenv(dotenv_path=_ENV_PATH, override=True)
        log_action(request, 'key_change', target_type='key', target_id=key)
        return Response({'status': 'updated', 'key': key})


# -------------------- APP SETTINGS --------------------

_ALLOWED_SETTINGS = frozenset({
    'SAMPLE_STORAGE_DIR', 'BACKUP_DIR', 'MAX_UPLOAD_SIZE_MB',
    # Email / password-reset settings
    'EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD',
    'EMAIL_USE_TLS', 'DEFAULT_FROM_EMAIL', 'FRONTEND_URL',
    'PASSWORD_RESET_ENABLED',
})


class AppSettingsView(APIView):
    """
    GET  /api/v1/admin/settings/ — return current application settings (staff only).
    POST /api/v1/admin/settings/ — update a setting in .env. Body: {key, value}.

    Writable settings: SAMPLE_STORAGE_DIR, BACKUP_DIR, MAX_UPLOAD_SIZE_MB.
    Database connection info is returned read-only.

    Note: changes write to the .env file and take effect immediately in the
    running process via load_dotenv(override=True).  In Docker they are lost
    on container restart unless the .env file is also persisted externally.
    """

    permission_classes = [IsStaffUser]

    def _db_info(self):
        db = settings.DATABASES.get('default', {})
        engine = db.get('ENGINE', '')
        if 'postgresql' in engine:
            engine_label = 'postgresql'
        elif 'sqlite' in engine:
            engine_label = 'sqlite'
        else:
            engine_label = engine.split('.')[-1]
        return {
            'engine': engine_label,
            'host': db.get('HOST', ''),
            'port': db.get('PORT', ''),
            'name': str(db.get('NAME', '')),
        }

    def _mask_password(self, value):
        if not value:
            return ''
        return f'{"*" * (len(value) - 4)}{value[-4:]}' if len(value) > 4 else '****'

    def get(self, request):
        raw_pw = os.getenv('EMAIL_HOST_PASSWORD', '')
        # Derive password_reset_enabled from the live env (may have changed since startup)
        email_host_configured = bool(os.getenv('EMAIL_HOST', '').strip())
        raw_enabled = os.getenv('PASSWORD_RESET_ENABLED')
        if raw_enabled is not None:
            password_reset_enabled = raw_enabled.strip().lower() == 'true'
        else:
            password_reset_enabled = email_host_configured

        return Response({
            'storage': {
                'sample_storage_dir': settings.SAMPLE_STORAGE_DIR,
                'backup_dir': settings.BACKUP_DIR,
            },
            'database': self._db_info(),
            'upload': {
                'max_upload_size_mb': int(os.getenv('MAX_UPLOAD_SIZE_MB', '200')),
            },
            'email': {
                'host': os.getenv('EMAIL_HOST', ''),
                'port': int(os.getenv('EMAIL_PORT', '587')),
                'host_user': os.getenv('EMAIL_HOST_USER', ''),
                'host_password': self._mask_password(raw_pw),
                'use_tls': os.getenv('EMAIL_USE_TLS', 'True').strip().lower() == 'true',
                'default_from': os.getenv('DEFAULT_FROM_EMAIL', 'noreply@vault1337.local'),
                'frontend_url': os.getenv('FRONTEND_URL', 'http://localhost:5173'),
                'password_reset_enabled': password_reset_enabled,
            },
        })

    def post(self, request):
        key = request.data.get('key', '').strip()
        value = request.data.get('value', '').strip()

        if not key or not value:
            return Response(
                {'detail': 'Both key and value are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if key not in _ALLOWED_SETTINGS:
            return Response(
                {'detail': f'Unknown setting "{key}". Allowed: {", ".join(sorted(_ALLOWED_SETTINGS))}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if key in ('SAMPLE_STORAGE_DIR', 'BACKUP_DIR'):
            if not os.path.isabs(value):
                return Response(
                    {'detail': f'{key} must be an absolute path (e.g. /app/sample_storage).'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if key == 'MAX_UPLOAD_SIZE_MB':
            try:
                mb = int(value)
                if mb <= 0:
                    raise ValueError
            except ValueError:
                return Response(
                    {'detail': 'MAX_UPLOAD_SIZE_MB must be a positive integer.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if key == 'EMAIL_PORT':
            try:
                port = int(value)
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                return Response(
                    {'detail': 'EMAIL_PORT must be an integer between 1 and 65535.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if key in ('EMAIL_USE_TLS', 'PASSWORD_RESET_ENABLED'):
            if value not in ('True', 'False'):
                return Response(
                    {'detail': f'{key} must be "True" or "False".'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if key == 'FRONTEND_URL':
            if not (value.startswith('http://') or value.startswith('https://')):
                return Response(
                    {'detail': 'FRONTEND_URL must start with http:// or https://.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        set_key(_ENV_PATH, key, value)
        load_dotenv(dotenv_path=_ENV_PATH, override=True)
        log_action(request, 'key_change', target_type='setting', target_id=key)
        return Response({'status': 'updated', 'key': key})


# -------------------- SSO CONFIG (PUBLIC) + SSO EXCHANGE --------------------

class SSOConfigView(APIView):
    """
    GET /api/v1/auth/sso/config/

    Returns SSO configuration for the frontend login page.  Unauthenticated —
    the login page needs this before the user is logged in.
    """

    permission_classes = [AllowAny]

    def get(self, request):
        enabled = getattr(settings, 'SSO_ENABLED', False)
        provider = getattr(settings, 'SSO_PROVIDER', '')
        allow_local = getattr(settings, 'SSO_ALLOW_LOCAL_LOGIN', True)

        # Build the PSA login URL for the configured provider.
        login_url = None
        if enabled and provider:
            login_url = f'/social/login/{provider}/'

        return Response({
            'enabled': enabled,
            'provider': provider,
            'allow_local_login': allow_local,
            'login_url': login_url,
        })


class SSOExchangeView(APIView):
    """
    POST /api/v1/auth/sso/exchange/

    Exchanges a short-lived SSO code (issued by SSOCompleteView after a
    successful OAuth callback) for a JWT token pair.

    Body: { "code": "<exchange code>" }
    Returns: { "access": "...", "refresh": "..." }

    The code is single-use and expires after 5 minutes.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        code = request.data.get('code', '').strip()
        if not code:
            return Response({'detail': 'code is required.'}, status=status.HTTP_400_BAD_REQUEST)

        from vault.sso import consume_sso_code

        result = consume_sso_code(request, code)
        if result is None:
            return Response(
                {'detail': 'Invalid or expired SSO code.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access, refresh = result
        return Response({'access': access, 'refresh': refresh})


# -------------------- SSO ADMIN (STAFF) --------------------

_SSO_SETTING_NAMES = (
    'SSO_ENABLED',
    'SSO_PROVIDER',
    'SSO_CLIENT_ID',
    'SSO_CLIENT_SECRET',
    'SSO_TENANT_ID',
    'SSO_METADATA_URL',
    'SSO_AUTO_PROVISION',
    'SSO_DEFAULT_ROLE',
    'SSO_ALLOW_LOCAL_LOGIN',
)
_SSO_SECRET_KEYS = frozenset({'SSO_CLIENT_SECRET'})


class SSOAdminView(APIView):
    """
    GET  /api/v1/admin/sso/ — return current SSO config (secrets masked).
    POST /api/v1/admin/sso/ — update one or more SSO settings in .env.

    Staff only.  Secret values are masked on GET (last 4 chars visible).
    On POST, omit a secret key (or send an empty string) to leave it unchanged.
    """

    permission_classes = [IsStaffUser]

    @staticmethod
    def _mask(value: str) -> str:
        if not value:
            return '(not set)'
        return f'{"*" * (len(value) - 4)}{value[-4:]}' if len(value) > 4 else '****'

    def get(self, request):
        result = {}
        for key in _SSO_SETTING_NAMES:
            value = os.getenv(key, '')
            result[key] = self._mask(value) if key in _SSO_SECRET_KEYS else value
        return Response(result)

    def post(self, request):
        updates = request.data
        if not isinstance(updates, dict):
            return Response({'detail': 'Expected a JSON object.'}, status=status.HTTP_400_BAD_REQUEST)

        for key, value in updates.items():
            if key not in _SSO_SETTING_NAMES:
                return Response(
                    {'detail': f'Unknown SSO setting: {key}'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not isinstance(value, str):
                return Response(
                    {'detail': f'{key} must be a string.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # For secret keys: skip update if the value is blank or still the
            # masked placeholder (user didn't type a new value).
            if key in _SSO_SECRET_KEYS and (not value or value.startswith('*')):
                continue
            set_key(_ENV_PATH, key, value)

        load_dotenv(dotenv_path=_ENV_PATH, override=True)
        log_action(request, 'key_change', target_type='sso', detail={'keys': list(updates.keys())})
        return Response({'status': 'updated'})


# -------------------- AUDIT LOG --------------------

class AuditLogView(APIView):
    """GET /api/v1/admin/audit/ — paginated audit log (staff only).

    Query params:
        action      — filter by action codename (e.g. file_upload)
        username    — filter by username substring
        limit       — max entries to return (default 100, max 500)
        offset      — skip N entries (for pagination)
    """

    permission_classes = [IsStaffUser]

    def get(self, request):
        qs = AuditLog.objects.select_related('user').order_by('-timestamp')

        action_filter = request.query_params.get('action', '').strip()
        if action_filter:
            qs = qs.filter(action=action_filter)

        username_filter = request.query_params.get('username', '').strip()
        if username_filter:
            qs = qs.filter(username__icontains=username_filter)

        try:
            limit = min(int(request.query_params.get('limit', 100)), 500)
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            limit, offset = 100, 0

        total = qs.count()
        entries = qs[offset: offset + limit]
        return Response({
            'total': total,
            'limit': limit,
            'offset': offset,
            'results': AuditLogSerializer(entries, many=True).data,
        })


class AuditPurgeView(APIView):
    """POST /api/v1/admin/audit/purge/ — delete audit records older than AUDIT_LOG_RETENTION_DAYS (staff only)."""

    permission_classes = [IsStaffUser]

    def post(self, request):
        from django.utils import timezone as _tz
        retention_days = getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 365)
        cutoff = _tz.now() - timedelta(days=retention_days)
        deleted, _ = AuditLog.objects.filter(timestamp__lt=cutoff).delete()
        log_action(request, 'backup_run', target_type='system',
                   detail={'purged_audit_records': deleted, 'retention_days': retention_days})
        return Response({'deleted': deleted, 'retention_days': retention_days})


class LockoutView(APIView):
    """
    GET  /api/v1/admin/auth/lockouts/ — list currently locked-out usernames (staff only).
    POST /api/v1/admin/auth/lockouts/ — clear lockout for a username. Body: {username}.
    """

    permission_classes = [IsStaffUser]

    def get(self, request):
        from django.utils import timezone as _tz
        cutoff = _tz.now() - timedelta(minutes=_LOCKOUT_WINDOW_MINUTES)
        locked = (
            FailedLoginAttempt.objects
            .filter(timestamp__gte=cutoff)
            .values('username')
            .annotate(count=Count('id'))
            .filter(count__gte=_LOCKOUT_THRESHOLD)
            .values_list('username', flat=True)
        )
        return Response({'locked_usernames': list(locked)})

    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({'detail': 'username is required.'}, status=status.HTTP_400_BAD_REQUEST)
        FailedLoginAttempt.objects.filter(username__iexact=username).delete()
        log_action(request, 'account_unlock', target_type='user', target_id=username,
                   detail={'unlocked_by': request.user.username})
        return Response({'detail': f'Lockout cleared for {username}.'})


# -------------------- HEALTH ENDPOINT --------------------

class HealthView(APIView):
    """GET /api/v1/health/ — liveness/readiness probe for load balancers and container orchestrators.

    No authentication required so health checks work before a JWT is issued.
    Returns HTTP 200 when all checks pass, HTTP 503 when any check fails.
    """

    permission_classes = [AllowAny]

    def get(self, request):
        db = _check_db_health()
        storage = _check_storage_health()
        all_ok = db['ok'] and storage['ok']
        payload = {
            'status': 'ok' if all_ok else 'degraded',
            'database': db,
            'storage': storage,
        }
        return Response(payload, status=status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE)


# -------------------- DASHBOARD STATS --------------------

def _check_db_health():
    """Return a dict with ok, latency_ms, and optional error string."""
    t0 = time.perf_counter()
    try:
        with db_connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        return {'ok': True, 'latency_ms': latency_ms, 'error': None}
    except Exception as exc:
        return {'ok': False, 'latency_ms': None, 'error': str(exc)}


def _check_storage_health():
    """Return a dict with ok, backend, path, and optional error string."""
    storage_dir = settings.SAMPLE_STORAGE_DIR
    try:
        probe = os.path.join(storage_dir, '.health_probe')
        with open(probe, 'w') as fh:
            fh.write('ok')
        os.remove(probe)
        return {'ok': True, 'backend': 'local', 'path': storage_dir, 'error': None}
    except Exception as exc:
        return {'ok': False, 'backend': 'local', 'path': storage_dir, 'error': str(exc)}


class DashboardStatsView(APIView):
    """GET /api/v1/admin/dashboard/ — management dashboard statistics (staff only)."""

    permission_classes = [IsStaffUser]

    def get(self, request):
        # Samples by submitter
        samples_by_submitter = list(
            File.objects.values('uploaded_by__username')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Total disk usage from stored file sizes
        disk_bytes = File.objects.aggregate(total=Sum('size'))['total'] or 0

        # File type breakdown by MIME (top 15)
        file_type_breakdown = list(
            File.objects.values('mime')
            .annotate(count=Count('id'))
            .order_by('-count')[:15]
        )

        # YARA rules on disk
        yara_dir = settings.YARA_RULES_DIR
        try:
            yara_count = len([f for f in os.listdir(yara_dir) if f.endswith('.yar')])
        except OSError:
            yara_count = 0

        return Response({
            'samples_by_submitter': [
                {'username': r['uploaded_by__username'] or 'Unknown', 'count': r['count']}
                for r in samples_by_submitter
            ],
            'disk_bytes_used': disk_bytes,
            'file_type_breakdown': [
                {'mime': r['mime'] or 'unknown', 'count': r['count']}
                for r in file_type_breakdown
            ],
            'counts': {
                'files': File.objects.count(),
                'iocs': IOC.objects.count(),
                'analysis_results': AnalysisResult.objects.count(),
                'comments': Comment.objects.count(),
                'users': User.objects.count(),
                'yara_rules': yara_count,
            },
            'health': {
                'database': _check_db_health(),
                'storage': _check_storage_health(),
            },
        })


# -------------------- CYBERCHEF MANAGEMENT --------------------

_CYBERCHEF_PUBLIC_DIR = os.path.join(settings.BASE_DIR, 'frontend', 'public', 'cyberchef')
_CYBERCHEF_DIST_DIR = os.path.join(settings.BASE_DIR, 'frontend', 'dist', 'cyberchef')
_GITHUB_CYBERCHEF_LATEST = 'https://api.github.com/repos/gchq/CyberChef/releases/latest'


def _cyberchef_current_version():
    """Detect installed CyberChef version from the versioned HTML filename."""
    for directory in (_CYBERCHEF_DIST_DIR, _CYBERCHEF_PUBLIC_DIR):
        if not os.path.isdir(directory):
            continue
        for fname in os.listdir(directory):
            m = re.match(r'CyberChef_(v[\d.]+)\.html', fname)
            if m:
                return m.group(1)
    return 'unknown'


class CyberChefVersionView(APIView):
    """
    GET /api/v1/admin/cyberchef/version/ — installed CyberChef version (staff only).

    By default returns only the locally-detected version to avoid an unnecessary
    GitHub API call on every page load.  Pass ?check_github=1 to also fetch the
    latest release tag from GitHub (triggered by the "Check for Updates" button).
    """

    permission_classes = [IsStaffUser]

    def get(self, request):
        current = _cyberchef_current_version()
        latest = None
        release_url = None

        if request.query_params.get('check_github') == '1':
            try:
                resp = requests.get(
                    _GITHUB_CYBERCHEF_LATEST,
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    latest = data.get('tag_name')
                    release_url = data.get('html_url')
            except Exception as exc:
                logger.warning("CyberChef version check failed: %s", exc)

        return Response({
            'current_version': current,
            'latest_version': latest,
            'release_url': release_url,
            'up_to_date': (current == latest) if latest else None,
        })


class CyberChefUpdateView(APIView):
    """POST /api/v1/admin/cyberchef/update/ — download and install latest CyberChef (staff only)."""

    permission_classes = [IsStaffUser]

    def post(self, request):
        import io
        import shutil
        import tempfile
        import zipfile

        # Fetch release metadata from GitHub
        try:
            meta_resp = requests.get(
                _GITHUB_CYBERCHEF_LATEST,
                headers={'Accept': 'application/vnd.github.v3+json'},
                timeout=10,
            )
            meta_resp.raise_for_status()
            release_data = meta_resp.json()
        except Exception as exc:
            logger.error("CyberChef update: failed to fetch release metadata: %s", exc)
            return Response(
                {'detail': f'Failed to fetch release metadata: {exc}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        latest_version = release_data.get('tag_name', 'unknown')

        # Find the zip asset
        zip_asset = next(
            (
                a for a in release_data.get('assets', [])
                if a['name'].lower().endswith('.zip') and 'cyberchef' in a['name'].lower()
            ),
            None,
        )
        if not zip_asset:
            return Response(
                {'detail': 'Could not find a CyberChef zip in the release assets.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Download zip
        try:
            dl_resp = requests.get(zip_asset['browser_download_url'], timeout=180, stream=True)
            dl_resp.raise_for_status()
            zip_bytes = dl_resp.content
        except Exception as exc:
            logger.error("CyberChef update: download failed: %s", exc)
            return Response(
                {'detail': f'Download failed: {exc}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        # Extract to temp dir, then copy files into the target directories
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    zf.extractall(tmp_dir)

                # Handle zips that place files inside a single top-level directory
                items = os.listdir(tmp_dir)
                src_dir = tmp_dir
                if len(items) == 1 and os.path.isdir(os.path.join(tmp_dir, items[0])):
                    src_dir = os.path.join(tmp_dir, items[0])

                # Update public/ (source) and dist/ (served by WhiteNoise), skipping missing dirs
                for target in (_CYBERCHEF_PUBLIC_DIR, _CYBERCHEF_DIST_DIR):
                    if not os.path.isdir(target):
                        continue
                    # Remove stale versioned HTML files so the version detector
                    # cannot pick up the old release after the update.
                    for existing in os.listdir(target):
                        if re.match(r'CyberChef_v[\d.]+\.html', existing):
                            os.remove(os.path.join(target, existing))
                    for fname in os.listdir(src_dir):
                        src_file = os.path.join(src_dir, fname)
                        if os.path.isfile(src_file):
                            shutil.copy2(src_file, os.path.join(target, fname))
        except Exception as exc:
            logger.error("CyberChef update: extraction failed: %s", exc)
            return Response(
                {'detail': f'Extraction failed: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        logger.info("CyberChef updated to %s by %s", latest_version, request.user.username)
        log_action(request, 'cyberchef_update', target_type='system',
                   detail={'version': latest_version})
        return Response({'status': 'updated', 'version': latest_version})


# -------------------- BACKUP --------------------

_BACKUP_FILENAME_PREFIX = 'vault1337_db_'
_BACKUP_FILENAME_SUFFIX = '.sql.gz'
_MAX_BACKUP_LISTINGS = 20


def _list_backups():
    """Return a list of backup metadata dicts sorted newest-first."""
    backup_dir = settings.BACKUP_DIR
    if not os.path.isdir(backup_dir):
        return []
    entries = []
    for name in os.listdir(backup_dir):
        if name.startswith(_BACKUP_FILENAME_PREFIX) and name.endswith(_BACKUP_FILENAME_SUFFIX):
            path = os.path.join(backup_dir, name)
            try:
                stat = os.stat(path)
                entries.append({
                    'filename': name,
                    'size_bytes': stat.st_size,
                    'created_at': datetime.utcfromtimestamp(stat.st_mtime).strftime('%Y-%m-%dT%H:%M:%SZ'),
                })
            except OSError:
                pass
    entries.sort(key=lambda e: e['created_at'], reverse=True)
    return entries[:_MAX_BACKUP_LISTINGS]


def _run_pg_dump(db_cfg, dest_path):
    """Run pg_dump and write gzip-compressed output to dest_path.

    Raises RuntimeError on failure.
    """
    env = os.environ.copy()
    env['PGPASSWORD'] = db_cfg.get('PASSWORD', '')
    cmd = [
        'pg_dump',
        '-h', db_cfg.get('HOST', 'localhost'),
        '-p', str(db_cfg.get('PORT', 5432)),
        '-U', db_cfg.get('USER', ''),
        '-d', db_cfg.get('NAME', ''),
        '--no-password',
        '--format=plain',
    ]
    result = subprocess.run(cmd, capture_output=True, env=env, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors='replace').strip())
    with gzip.open(dest_path, 'wb') as fh:
        fh.write(result.stdout)


class BackupStatusView(APIView):
    """GET /api/v1/admin/backup/status/ — list recent database backups (staff only)."""

    permission_classes = [IsStaffUser]

    def get(self, request):
        backups = _list_backups()
        return Response({
            'backup_dir': settings.BACKUP_DIR,
            'backups': backups,
            'latest': backups[0] if backups else None,
        })


class BackupRunView(APIView):
    """POST /api/v1/admin/backup/db/ — trigger an immediate pg_dump backup (staff only).

    Only supported when the active database engine is PostgreSQL.
    Returns the filename and size of the created backup on success.
    """

    permission_classes = [IsStaffUser]

    def post(self, request):
        db_cfg = settings.DATABASES.get('default', {})
        engine = db_cfg.get('ENGINE', '')
        if 'postgresql' not in engine and 'postgres' not in engine:
            return Response(
                {'detail': 'Database backup is only supported for PostgreSQL. '
                           'SQLite databases can be backed up by copying the db.sqlite3 file.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        backup_dir = settings.BACKUP_DIR
        try:
            os.makedirs(backup_dir, exist_ok=True)
        except OSError as exc:
            logger.error("Backup: could not create backup dir %s: %s", backup_dir, exc)
            return Response({'detail': f'Cannot create backup directory: {exc}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{_BACKUP_FILENAME_PREFIX}{timestamp}{_BACKUP_FILENAME_SUFFIX}"
        dest_path = os.path.join(backup_dir, filename)

        try:
            _run_pg_dump(db_cfg, dest_path)
        except FileNotFoundError:
            return Response(
                {'detail': 'pg_dump not found. Ensure postgresql-client is installed in the container.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except subprocess.TimeoutExpired:
            return Response({'detail': 'pg_dump timed out after 300 seconds.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as exc:
            logger.error("Backup: pg_dump failed: %s", exc)
            return Response({'detail': f'pg_dump failed: {exc}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        size_bytes = os.path.getsize(dest_path)
        logger.info("Backup: created %s (%d bytes) by %s", filename, size_bytes, request.user)
        log_action(request, 'backup_run', target_type='system', target_id=filename,
                   detail={'size_bytes': size_bytes, 'backup_dir': backup_dir})
        return Response({
            'status': 'ok',
            'filename': filename,
            'size_bytes': size_bytes,
            'backup_dir': backup_dir,
        }, status=status.HTTP_201_CREATED)


# -------------------- VT DOWNLOAD --------------------

class VTDownloadView(APIView):
    """
    POST /api/v1/files/vt-download/

    Body: { "sha256": "<64-char hex>", "tags": "optional,csv" }
    Downloads the file from VirusTotal and stores it in sample storage.
    Requires a VirusTotal Enterprise API key.
    """

    permission_classes = [IsAuthenticated, vault_perm('upload_sample')]

    def post(self, request):
        sha256_raw = request.data.get('sha256', '').strip()
        tags_raw = request.data.get('tags', '')

        if not sha256_raw:
            return Response({'detail': 'sha256 is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            clean_sha256 = validate_sha256(sha256_raw)
        except ValueError:
            return Response({'detail': 'Invalid SHA256 hash.'}, status=status.HTTP_400_BAD_REQUEST)

        vtkey = get_api_key('VT_KEY')
        if not vtkey or vtkey == 'paste_your_api_key_here':
            return Response(
                {'detail': 'VirusTotal API key not configured.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        url = f"https://www.virustotal.com/api/v3/files/{clean_sha256}/download"
        headers = {"accept": "application/json", "x-apikey": vtkey}
        try:
            vt_response = requests.get(url, headers=headers, timeout=30)
        except Exception as e:
            logger.error("VT download request failed for %s: %s", clean_sha256, e)
            return Response({'detail': 'Error contacting VirusTotal.'}, status=status.HTTP_502_BAD_GATEWAY)

        if vt_response.status_code == 403:
            return Response(
                {'detail': 'VirusTotal Enterprise licence required to download files.'},
                status=status.HTTP_403_FORBIDDEN,
            )
        if vt_response.status_code != 200:
            return Response(
                {'detail': f'VirusTotal returned {vt_response.status_code}.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        tags = [t.strip() for t in tags_raw.split(',') if t.strip()]
        tags.append('virustotal')

        # Write to an OS-generated tempfile so no user-derived value reaches
        # open(), hash_sample(), or os.rename(). Tempfile paths carry no taint.
        tmp_fd, tmp_path = tempfile.mkstemp(dir=settings.SAMPLE_STORAGE_DIR)
        try:
            with os.fdopen(tmp_fd, 'wb') as fh:
                fh.write(vt_response.content)
        except OSError as e:
            os.unlink(tmp_path)
            logger.error("Could not write VT download for %s: %s", clean_sha256, e)
            return Response({'detail': 'Error saving file.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        from vault.utils import hash_sample
        md5, sha1, sha256_hash, sha512, magic_byte, size, mime = hash_sample(tmp_path)

        if sha256_hash != clean_sha256:
            os.unlink(tmp_path)
            logger.warning("VT hash mismatch: requested %s, got %s", clean_sha256, sha256_hash)
            return Response(
                {'detail': 'Hash mismatch: downloaded file does not match requested SHA256.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if File.objects.filter(sha256=sha256_hash).exists():
            os.unlink(tmp_path)
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        # final_path derives from the hashlib digest — not from user input.
        final_path = os.path.join(settings.SAMPLE_STORAGE_DIR, sha256_hash)
        os.rename(tmp_path, final_path)

        file_obj = File(
            name=clean_sha256,
            size=size,
            magic=magic_byte,
            mime=mime,
            md5=md5,
            sha1=sha1,
            sha256=sha256_hash,
            sha512=sha512,
            uploaded_by=request.user,
        )
        file_obj.save()
        for tag in tags:
            file_obj.tag.add(tag.lower())
        file_obj.save()

        log_action(request, 'file_upload', target_type='file', target_id=file_obj.sha256,
                   detail={'source': 'virustotal', 'name': file_obj.name, 'size': file_obj.size})

        vt_result = fetch_vt_report(file_obj.sha256)
        if vt_result is not None:
            file_obj.vt_data = vt_result
            file_obj.save(update_fields=['vt_data'])
            threat_label = (vt_result.get('popular_threat_classification') or {}).get('suggested_threat_label', '')
            if threat_label:
                file_obj.tag.add(threat_label.lower())

        return Response(
            FileSerializer(file_obj, context={'request': request}).data,
            status=status.HTTP_201_CREATED,
        )


# -------------------- MB DOWNLOAD --------------------

class MBDownloadView(APIView):
    """
    POST /api/v1/files/mb-download/

    Body: { "sha256": "<64-char hex>", "tags": "optional,csv" }
    Downloads the file from MalwareBazaar and stores it in sample storage.
    """

    permission_classes = [IsAuthenticated, vault_perm('upload_sample')]

    def post(self, request):
        sha256_raw = request.data.get('sha256', '').strip()
        tags_raw = request.data.get('tags', '')

        if not sha256_raw:
            return Response({'detail': 'sha256 is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            clean_sha256 = validate_sha256(sha256_raw)
        except ValueError:
            return Response({'detail': 'Invalid SHA256 hash.'}, status=status.HTTP_400_BAD_REQUEST)

        if File.objects.filter(sha256=clean_sha256).exists():
            return Response({'detail': 'File already exists.'}, status=status.HTTP_409_CONFLICT)

        mbkey = get_api_key('MALWARE_BAZAAR_KEY')
        samples_dir = settings.SAMPLE_STORAGE_DIR

        try:
            headers = {'Auth-Key': mbkey} if mbkey else {}
            data = {'query': 'get_file', 'sha256_hash': clean_sha256}
            mb_response = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data=data,
                timeout=30,
                headers=headers,
                allow_redirects=True,
            )
        except Exception as e:
            logger.error("MB download request failed for %s: %s", clean_sha256, e)
            return Response({'detail': 'Error contacting MalwareBazaar.'}, status=status.HTTP_502_BAD_GATEWAY)

        if mb_response.status_code != 200:
            return Response(
                {'detail': f'MalwareBazaar returned {mb_response.status_code}.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        # MalwareBazaar returns HTTP 200 for both success and errors, and
        # always sends Content-Type: application/json regardless. Distinguish
        # by sniffing the first byte: ZIP files start with PK (0x50 0x4B),
        # JSON error bodies start with '{'.
        if mb_response.content[:1] == b'{':
            try:
                mb_json = mb_response.json()
                qs = mb_json.get('query_status', '')
            except Exception:
                qs = ''
            if qs == 'unauthorized':
                return Response(
                    {'detail': 'MalwareBazaar rejected the API key. Check your Auth-Key in API settings.'},
                    status=status.HTTP_502_BAD_GATEWAY,
                )
            if qs == 'no_results':
                return Response(
                    {'detail': 'MalwareBazaar: no results found for this hash.'},
                    status=status.HTTP_404_NOT_FOUND,
                )
            return Response(
                {'detail': f'MalwareBazaar error: {qs or "unexpected response"}.'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        # Use OS-generated tempfile paths throughout so no user-derived value
        # (sha256, zip entry name) reaches open(), os.remove(), hash_sample(),
        # or os.rename(). Tempfile paths carry no request-body taint.
        tmp_zip_path = None
        tmp_path = None
        try:
            tmp_zip_fd, tmp_zip_path = tempfile.mkstemp(dir=samples_dir)
            with os.fdopen(tmp_zip_fd, 'wb') as fh:
                fh.write(mb_response.content)

            with pyzipper.AESZipFile(tmp_zip_path) as zf:
                extracted = zf.filelist[0]
                # Read bytes directly — the entry name is only validated for
                # emptiness; it never influences any file system path.
                if not os.path.basename(extracted.filename):
                    raise ValueError("Archive entry has an empty or directory-only name.")
                file_data = zf.read(extracted, pwd=b'infected')

            os.remove(tmp_zip_path)
            tmp_zip_path = None

            tmp_fd, tmp_path = tempfile.mkstemp(dir=samples_dir)
            with os.fdopen(tmp_fd, 'wb') as fh:
                fh.write(file_data)

        except Exception as e:
            logger.error("MB unzip failed for %s: %s", clean_sha256, e)
            for p in (tmp_zip_path, tmp_path):
                if p and os.path.isfile(p):
                    os.remove(p)
            return Response(
                {'detail': f'Error extracting archive: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Fetch metadata from MB
        filename = clean_sha256
        content_type = 'application/octet-stream'
        try:
            info_resp = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data={'query': 'get_info', 'hash': clean_sha256},
                timeout=15,
                headers=headers,
            )
            if info_resp.status_code == 200:
                info = info_resp.json()
                raw_name = info['data'][0].get('file_name', '') or ''
                raw_mime = info['data'][0].get('file_type_mime', '') or ''
                # Sanitise: keep only safe filename characters, cap at 255 chars.
                # Fall back to the SHA256 if sanitisation produces an empty string.
                safe_name = re.sub(r'[^a-zA-Z0-9._\-]', '_', raw_name)[:255].strip('_')
                filename = safe_name if safe_name else clean_sha256
                content_type = raw_mime[:100] if raw_mime else 'application/octet-stream'
        except Exception as e:
            logger.warning("Could not fetch MB metadata for %s: %s", clean_sha256, e)

        from vault.utils import hash_sample
        md5, sha1, sha256_hash, sha512, magic_byte, size, mime = hash_sample(tmp_path)

        # final_path derives from the hashlib digest — not from user input.
        final_path = os.path.join(samples_dir, sha256_hash)
        os.rename(tmp_path, final_path)

        tags = [t.strip() for t in tags_raw.split(',') if t.strip()]
        tags.append('malwarebazaar')

        file_obj = File(
            name=filename,
            size=size,
            magic=magic_byte,
            mime=content_type,
            md5=md5,
            sha1=sha1,
            sha256=sha256_hash,
            sha512=sha512,
            uploaded_by=request.user,
        )
        file_obj.save()
        for tag in tags:
            file_obj.tag.add(tag.lower())
        file_obj.save()

        log_action(request, 'file_upload', target_type='file', target_id=file_obj.sha256,
                   detail={'source': 'malwarebazaar', 'name': file_obj.name, 'size': file_obj.size})

        vt_result = fetch_vt_report(file_obj.sha256)
        if vt_result is not None:
            file_obj.vt_data = vt_result
            file_obj.save(update_fields=['vt_data'])
            threat_label = (vt_result.get('popular_threat_classification') or {}).get('suggested_threat_label', '')
            if threat_label:
                file_obj.tag.add(threat_label.lower())

        return Response(
            FileSerializer(file_obj, context={'request': request}).data,
            status=status.HTTP_201_CREATED,
        )


# -------------------- QR DECODE --------------------

class QRDecodeView(APIView):
    """
    POST /api/v1/tools/qr-decode/

    Accepts a PNG image as a multipart upload, decodes any QR code found in
    it using OpenCV, and returns the decoded text.  The file is not stored in
    the vault — this is a stateless decode-only operation.
    """

    permission_classes = [IsAuthenticated, vault_perm('run_tools')]

    def post(self, request):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response({'detail': 'No file provided.'}, status=status.HTTP_400_BAD_REQUEST)

        from vault.workbench.qr_decode import decode_qr
        result = decode_qr(uploaded_file)
        return Response({'result': result})
