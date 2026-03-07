"""
Android APK analysis tool using androguard.

Sub-tools:
  manifest    — package name, version, SDK levels, declared permissions
  components  — activities, services, receivers, providers
  intents     — intent filters grouped by component
  certificate — signing certificate details (v1/v2/v3 schemes)
  strings     — meaningful strings extracted from DEX bytecode
  urls        — URLs and IP addresses found in DEX strings
  suspicious  — dangerous permissions + suspicious API class usage
"""

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

_MAX_SIZE = 100 * 1024 * 1024  # 100 MB cap

# Dangerous permissions that warrant analyst attention
_DANGEROUS_PERMISSIONS = {
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.CALL_PHONE',
    'android.permission.USE_BIOMETRIC',
    'android.permission.USE_FINGERPRINT',
    'android.permission.GET_ACCOUNTS',
    'android.permission.BLUETOOTH_SCAN',
    'android.permission.BLUETOOTH_CONNECT',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.INSTALL_PACKAGES',
    'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.DELETE_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'android.permission.BIND_DEVICE_ADMIN',
    'android.permission.CHANGE_NETWORK_STATE',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.FOREGROUND_SERVICE',
    'android.permission.DISABLE_KEYGUARD',
    'android.permission.WAKE_LOCK',
    'android.permission.REORDER_TASKS',
    'android.permission.KILL_BACKGROUND_PROCESSES',
}

# Suspicious API classes — presence in DEX method references is notable
_SUSPICIOUS_APIS = [
    ('Ljava/lang/Runtime;',              'Shell execution (Runtime.exec)'),
    ('Ljava/lang/ProcessBuilder;',       'Shell execution (ProcessBuilder)'),
    ('Ldalvik/system/DexClassLoader;',   'Dynamic code loading (DexClassLoader)'),
    ('Ldalvik/system/PathClassLoader;',  'Dynamic code loading (PathClassLoader)'),
    ('Ldalvik/system/InMemoryDexClassLoader;', 'In-memory DEX loading'),
    ('Ljava/lang/reflect/Method;',       'Reflection'),
    ('Ljava/lang/reflect/Field;',        'Reflection'),
    ('Landroid/telephony/SmsManager;',   'SMS access'),
    ('Landroid/telephony/TelephonyManager;', 'Device/call info (IMEI, subscriber ID)'),
    ('Landroid/location/LocationManager;', 'Location access'),
    ('Landroid/net/wifi/WifiManager;',   'Wi-Fi scanning/manipulation'),
    ('Ljava/net/HttpURLConnection;',     'HTTP networking'),
    ('Ljavax/net/ssl/SSLContext;',       'Custom SSL context (cert pinning bypass risk)'),
    ('Landroid/app/admin/DevicePolicyManager;', 'Device admin (ransomware/stalkerware)'),
    ('Landroid/accessibilityservice/AccessibilityService;', 'Accessibility service (keylogging/overlay risk)'),
    ('Landroid/content/pm/PackageInstaller;', 'Package installation'),
    ('Ljavax/crypto/Cipher;',            'Cryptography (encryption/decryption)'),
    ('Landroid/provider/ContactsContract;', 'Contacts access'),
    ('Landroid/provider/CallLog;',       'Call log access'),
    ('Landroid/media/AudioRecord;',      'Audio recording'),
    ('Landroid/hardware/camera2/CameraManager;', 'Camera access'),
]

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


def apk_subtool(file_path: str, sub_tool: str) -> str:
    """Dispatch an APK analysis sub-tool."""
    if not ANDROGUARD_AVAILABLE:
        return '[!] androguard is not installed. Run: pip install androguard'

    import os
    if not os.path.isfile(file_path):
        return '[!] File not found.'

    file_size = os.path.getsize(file_path)
    if file_size > _MAX_SIZE:
        return f'[!] APK too large ({file_size // (1024 * 1024)} MB > 100 MB limit).'

    dispatch = {
        'manifest':    _manifest,
        'components':  _components,
        'intents':     _intents,
        'certificate': _certificate,
        'strings':     _strings,
        'urls':        _urls,
        'suspicious':  _suspicious,
    }

    fn = dispatch.get(sub_tool)
    if fn is None:
        return f'[!] Unknown sub-tool: {sub_tool!r}'

    try:
        apk, dex_list, dx = AnalyzeAPK(file_path)
    except Exception as exc:
        logger.warning('apk_tool: AnalyzeAPK failed for %s: %s', file_path, exc)
        return f'[!] Failed to parse APK: {exc}'

    try:
        return fn(apk, dex_list, dx)
    except Exception as exc:
        logger.warning('apk_tool: sub-tool %s failed: %s', sub_tool, exc)
        return f'[!] Error in {sub_tool}: {exc}'


# ── sub-tool implementations ──────────────────────────────────────────────────

def _manifest(apk, dex_list, dx) -> str:
    lines = ['=== APK Manifest ===', '']

    def row(label, value):
        return f'  {label:<22} {value or "N/A"}'

    lines += [
        row('Package',         apk.get_package()),
        row('App name',        apk.get_app_name()),
        row('Version code',    str(apk.get_androidversion_code() or '')),
        row('Version name',    str(apk.get_androidversion_name() or '')),
        row('Min SDK',         str(apk.get_min_sdk_version() or '')),
        row('Target SDK',      str(apk.get_target_sdk_version() or '')),
        row('Main activity',   apk.get_main_activity()),
        '',
    ]

    perms = sorted(apk.get_permissions())
    dangerous = [p for p in perms if p in _DANGEROUS_PERMISSIONS]
    normal = [p for p in perms if p not in _DANGEROUS_PERMISSIONS]

    lines.append(f'Permissions ({len(perms)} total, {len(dangerous)} dangerous):')
    if dangerous:
        lines.append('  [!] Dangerous:')
        for p in dangerous:
            lines.append(f'      {p}')
    if normal:
        lines.append('  Normal:')
        for p in normal:
            lines.append(f'      {p}')
    if not perms:
        lines.append('  (none declared)')

    return '\n'.join(lines)


def _components(apk, dex_list, dx) -> str:
    lines = ['=== APK Components ===', '']

    def section(title, items):
        lines.append(f'{title} ({len(items)}):')
        if items:
            for item in sorted(items):
                marker = '  [MAIN] ' if item == apk.get_main_activity() else '  '
                lines.append(f'{marker}{item}')
        else:
            lines.append('  (none)')
        lines.append('')

    section('Activities',  apk.get_activities())
    section('Services',    apk.get_services())
    section('Receivers',   apk.get_receivers())
    section('Providers',   apk.get_providers())

    return '\n'.join(lines)


def _intents(apk, dex_list, dx) -> str:
    lines = ['=== Intent Filters ===', '']

    for comp_type in ('activity', 'service', 'receiver'):
        components = {
            'activity': apk.get_activities(),
            'service':  apk.get_services(),
            'receiver': apk.get_receivers(),
        }[comp_type]

        for name in sorted(components):
            try:
                filters = apk.get_intent_filters(comp_type, name)
            except Exception:
                continue
            if not filters:
                continue
            lines.append(f'[{comp_type.upper()}] {name}')
            for filter_type, values in filters.items():
                for v in values:
                    lines.append(f'  {filter_type}: {v}')
            lines.append('')

    if len(lines) == 2:
        lines.append('  No explicit intent filters declared.')

    return '\n'.join(lines)


def _certificate(apk, dex_list, dx) -> str:
    lines = ['=== Signing Certificate(s) ===', '']

    certs = []

    # Try v2/v3 scheme first (block-based signing)
    try:
        v2_certs = apk.get_certificates_der_v2()
        if v2_certs:
            certs.extend([(cert, 'v2/v3 block') for cert in v2_certs])
    except Exception:
        pass

    # Fall back to v1 (JAR signing) — parse from META-INF/*.RSA / *.DSA / *.EC
    if not certs:
        try:
            for name in apk.get_signature_names():
                try:
                    raw = apk.get_file(name)
                    if raw:
                        certs.append((raw, 'v1 JAR'))
                except Exception:
                    pass
        except Exception:
            pass

    if not certs:
        return '[?] No signing certificates found or could not be parsed.'

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        return '[!] cryptography library not available — cannot parse certificate details.'

    for i, (raw, scheme) in enumerate(certs, 1):
        lines.append(f'Certificate {i} (scheme: {scheme})')
        try:
            # raw may be DER cert or PKCS7 blob — try both
            cert = None
            try:
                cert = x509.load_der_x509_certificate(raw)
            except Exception:
                try:
                    pkcs7_certs = pkcs7.load_der_pkcs7_certificates(raw)
                    if pkcs7_certs:
                        cert = pkcs7_certs[0]
                except Exception:
                    pass

            if cert is None:
                lines.append('  [!] Could not parse certificate.')
                continue

            def row(label, value):
                lines.append(f'  {label:<20} {value}')

            row('Subject',  cert.subject.rfc4514_string())
            row('Issuer',   cert.issuer.rfc4514_string())
            row('Valid from', str(cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before))
            row('Valid to',  str(cert.not_valid_after_utc  if hasattr(cert, 'not_valid_after_utc')  else cert.not_valid_after))
            row('Serial',    hex(cert.serial_number))

            sha1_fp = cert.fingerprint(hashes.SHA1()).hex(':')   # noqa: S324
            sha256_fp = cert.fingerprint(hashes.SHA256()).hex(':')
            row('SHA-1 FP',  sha1_fp)
            row('SHA-256 FP', sha256_fp)

            pub = cert.public_key()
            key_type = type(pub).__name__.replace('PublicKey', '')
            try:
                key_size = pub.key_size
            except AttributeError:
                key_size = '?'
            row('Public key', f'{key_type} {key_size}-bit')

            self_signed = cert.issuer == cert.subject
            row('Self-signed', 'Yes (debug/test cert)' if self_signed else 'No')

        except Exception as exc:
            lines.append(f'  [!] Parse error: {exc}')

        lines.append('')

    return '\n'.join(lines)


def _strings(apk, dex_list, dx) -> str:
    lines = ['=== DEX Strings ===', '']

    _MIN_LEN = 6
    _MAX_COUNT = 500
    _SKIP_PATTERNS = re.compile(
        r'^(Ljava|Landroid|Lkotlin|Lcom/google|Ldalvik|Ljavax|Lsun|Lorg/apache|Lorg/json'
        r'|V|Z|B|C|D|F|I|J|S|[VZBCDFIJS]\[|\[B|\[C|\[I|\[J'
        r'|<init>|<clinit>|toString|hashCode|equals|getClass)',
        re.IGNORECASE,
    )

    seen = set()
    collected = []
    for s_analysis in dx.get_strings_analysis().values():
        s = str(s_analysis.get_orig_value())
        if len(s) < _MIN_LEN:
            continue
        if _SKIP_PATTERNS.match(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        collected.append(s)
        if len(collected) >= _MAX_COUNT:
            break

    if not collected:
        lines.append('No meaningful strings found.')
    else:
        lines.append(f'{len(collected)} strings (capped at {_MAX_COUNT}):')
        lines.append('')
        for s in sorted(collected):
            lines.append(f'  {s}')

    return '\n'.join(lines)


def _urls(apk, dex_list, dx) -> str:
    lines = ['=== Embedded URLs & IPs ===', '']

    _URL_RE = re.compile(
        r'https?://[^\s\'"<>]{6,}',
        re.IGNORECASE,
    )
    _IP_RE = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b'
    )

    urls_found = set()
    ips_found = set()

    for s_analysis in dx.get_strings_analysis().values():
        s = str(s_analysis.get_orig_value())
        for m in _URL_RE.finditer(s):
            urls_found.add(m.group().rstrip('.,;)'))
        for m in _IP_RE.finditer(s):
            ip_str = m.group().split(':')[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if not addr.is_loopback and not addr.is_link_local:
                    ips_found.add(m.group())
            except ValueError:
                pass

    if urls_found:
        lines.append(f'URLs ({len(urls_found)}):')
        for u in sorted(urls_found):
            lines.append(f'  {u}')
        lines.append('')

    if ips_found:
        lines.append(f'IP addresses ({len(ips_found)}):')
        for ip in sorted(ips_found):
            lines.append(f'  {ip}')
        lines.append('')

    if not urls_found and not ips_found:
        lines.append('No URLs or IP addresses found in DEX strings.')

    return '\n'.join(lines)


def _suspicious(apk, dex_list, dx) -> str:
    lines = ['=== Suspicious Indicators ===', '']

    # ── Dangerous permissions ─────────────────────────────────────────────
    perms = set(apk.get_permissions())
    dangerous = sorted(p for p in perms if p in _DANGEROUS_PERMISSIONS)
    lines.append(f'Dangerous permissions ({len(dangerous)}):')
    if dangerous:
        for p in dangerous:
            short = p.replace('android.permission.', '')
            lines.append(f'  [!] {short}')
    else:
        lines.append('  None.')
    lines.append('')

    # ── Suspicious API classes in DEX ─────────────────────────────────────
    all_classes = {str(c.name) for c in dx.get_classes()}

    lines.append('Suspicious API usage:')
    found_any = False
    for cls_pattern, description in _SUSPICIOUS_APIS:
        # Match as exact class or prefix (inner classes)
        matched = any(
            c == cls_pattern or c.startswith(cls_pattern.rstrip(';') + '$')
            for c in all_classes
        )
        if matched:
            short = cls_pattern.strip('L').rstrip(';').replace('/', '.')
            lines.append(f'  [!] {short}')
            lines.append(f'      → {description}')
            found_any = True

    if not found_any:
        lines.append('  None detected.')
    lines.append('')

    # ── Exported components (attack surface) ─────────────────────────────
    try:
        exported = []
        for comp_type in ('activity', 'service', 'receiver'):
            components = {
                'activity': apk.get_activities(),
                'service':  apk.get_services(),
                'receiver': apk.get_receivers(),
            }[comp_type]
            for name in components:
                try:
                    filters = apk.get_intent_filters(comp_type, name)
                    if filters:
                        exported.append((comp_type, name))
                except Exception:
                    pass

        lines.append(f'Exported components with intent filters ({len(exported)}):')
        if exported:
            for comp_type, name in sorted(exported):
                lines.append(f'  [{comp_type.upper()}] {name}')
        else:
            lines.append('  None.')
    except Exception:
        pass

    return '\n'.join(lines)
