"""
Audit logging helper for vault1337.

Usage:
    from vault.audit import log_action
    log_action(request, 'file_upload', target_type='file', target_id=sha256,
               detail={'name': filename, 'size': size})

All action codenames are defined on AuditLog.ACTION_CHOICES in models.py.
Never log secret values (API keys, passwords) in the detail field.
"""
import logging

logger = logging.getLogger(__name__)


def _get_client_ip(request):
    """Return the real client IP, accounting for reverse-proxy X-Forwarded-For."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def log_action(request, action, *, target_type='', target_id='', detail=None):
    """Create an AuditLog row for an action.

    Args:
        request:     The DRF/Django request object. Used to extract the
                     authenticated user and client IP address.
        action:      One of the AuditLog.ACTION_CHOICES codenames.
        target_type: Category string — 'file', 'user', 'ioc', 'yara',
                     'key', 'role', 'system'.
        target_id:   Identifier for the affected object — SHA256, username,
                     rule name, etc.  Truncated to 200 chars.
        detail:      Optional dict with additional structured context.
                     Never include secrets (passwords, API key values).
    """
    # Import here to avoid circular imports at module load time.
    from vault.models import AuditLog  # noqa: PLC0415

    user = getattr(request, 'user', None)
    if user and not user.is_authenticated:
        user = None

    username = ''
    if user:
        username = user.username
    elif isinstance(detail, dict):
        # login / login_failed pass the attempted username in detail before auth succeeds
        username = detail.get('username', '') or detail.get('attempted_username', '')

    try:
        AuditLog.objects.create(
            user=user,
            username=username,
            action=action,
            target_type=target_type,
            target_id=str(target_id)[:200] if target_id else '',
            detail=detail,
            ip_address=_get_client_ip(request),
        )
    except Exception as exc:
        # Audit logging must never crash the request it wraps.
        logger.error("audit_log: failed to write entry (action=%s): %s", action, exc)
