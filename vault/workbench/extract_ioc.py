import ipaddress
import os
import re
import time
import logging
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse
from vault.models import File, IOC
import tldextract
from django.conf import settings as django_settings

logger = logging.getLogger(__name__)

# --- Configuration ---

TLD_CACHE_DIR = os.path.join(django_settings.BASE_DIR, 'vault', 'static', '.tld_set')
TLD_CACHE_FILE = os.path.join(TLD_CACHE_DIR, "public_suffix_list.dat")
MAX_CACHE_AGE = 7 * 24 * 60 * 60  # 7 days

# Ensure cache directory exists
os.makedirs(TLD_CACHE_DIR, exist_ok=True)

# Initialize extractor
tldextractor = tldextract.TLDExtract(cache_dir=TLD_CACHE_DIR)


def ensure_tld_cache_is_fresh():
    """Update the TLD cache if it's older than MAX_CACHE_AGE."""
    try:
        if os.path.exists(TLD_CACHE_FILE):
            file_age = time.time() - os.path.getmtime(TLD_CACHE_FILE)
            if file_age < MAX_CACHE_AGE:
                return
        tldextractor.update()
    except Exception as e:
        logger.exception(e)


# Ensure cache is up-to-date
ensure_tld_cache_is_fresh()


# --- IOC Patterns ---

IOC_PATTERNS = {
    # Negative lookbehind (?<!\w/) blocks version-string false positives such
    # as Chrome/120.0.0.0 or Safari/537.36 where a word character immediately
    # precedes a slash that precedes the number.  http://1.2.3.4 is safe
    # because the char before the IP is '/' preceded by ':', not a word char.
    "ip": re.compile(
        r'(?<!\w/)\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b',
        re.IGNORECASE
    ),
    # Stop at characters that are document syntax, not valid URL content:
    # whitespace, angle brackets (HTML/PDF/XML), parens, square/curly braces,
    # quotes, backtick, pipe, caret, backslash, and control chars.
    # Post-processing strips any trailing punctuation (period, comma, etc.)
    # that got included because it was immediately adjacent to the URL.
    "url": re.compile(
        r'(?:https?|ftp)://[^\s<>()\[\]{}"\'`|^\\<>\x00-\x1f]+',
        re.IGNORECASE
    ),
    # Negative lookbehind for $ and . prevents matching PowerShell/scripting
    # variable properties such as $results.Name or $obj.Count.  The $ is not
    # a word character so \b alone does not block it; the . lookbehind also
    # blocks mid-chain labels like $env.results.Name at every level.
    "domain": re.compile(
        r'(?<![.$])\b(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.)+(?P<tld>[a-zA-Z]{2,})\b'
    ),
    "bitcoin": re.compile(
        r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    ),
    "cve": re.compile(
        r'CVE-\d{4}-\d{4,7}',
        re.IGNORECASE
    ),
    "registry": re.compile(
        r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU)'
        r'\\[^\s"\'<>\n]{1,200}',
        re.IGNORECASE
    ),
    "named_pipe": re.compile(
        r'(?:\\\\.\\pipe\\|Global\\|Local\\)[^\s"\'<>\n]{1,100}',
        re.IGNORECASE
    ),
    # ── Persistence artefacts ─────────────────────────────────────────────────
    # Windows: Run/RunOnce/Services/Startup registry persistence paths
    "win_persistence": re.compile(
        r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)'
        r'\\(?:SOFTWARE\\)?(?:Microsoft\\Windows\\CurrentVersion\\'
        r'(?:Run(?:Once)?|Policies\\Explorer\\Run|RunServices(?:Once)?)|'
        r'SYSTEM\\(?:CurrentControlSet|ControlSet\d+)\\Services\\'
        r'[^\s"\'<>\n]{1,100})',
        re.IGNORECASE
    ),
    # Windows: Scheduled task file paths and schtasks command references
    "scheduled_task": re.compile(
        r'(?:'
        r'[A-Za-z]:\\Windows\\System32\\Tasks\\[^\s"\'<>\n]{1,150}'
        r'|[A-Za-z]:\\Windows\\SysWOW64\\Tasks\\[^\s"\'<>\n]{1,150}'
        r'|schtasks(?:\.exe)?\s+/[^\n]{0,200}'
        r'|at\.exe\s+[^\n]{0,200}'
        r')',
        re.IGNORECASE
    ),
    # Linux: cron persistence paths
    "linux_cron": re.compile(
        r'(?:/etc/cron(?:\.d/|tab|\.daily/|\.hourly/|\.weekly/|\.monthly/)'
        r'[^\s"\'<>\n]{0,100}'
        r'|/var/spool/cron(?:/crontabs)?/?[^\s"\'<>\n]{0,100})',
        re.IGNORECASE
    ),
    # Linux: systemd unit file paths
    "systemd_unit": re.compile(
        r'(?:/etc/systemd/(?:system|user)/[^\s"\'<>\n]{1,100}\.(?:service|timer|socket|mount|target|path)'
        r'|/usr/lib/systemd/(?:system|user)/[^\s"\'<>\n]{1,100}\.(?:service|timer|socket|mount|target|path)'
        r'|/lib/systemd/(?:system|user)/[^\s"\'<>\n]{1,100}\.(?:service|timer|socket|mount|target|path)'
        r'|~?/\.config/systemd/user/[^\s"\'<>\n]{1,100}\.(?:service|timer|socket|mount|target|path))',
        re.IGNORECASE
    ),
    # macOS: LaunchAgent / LaunchDaemon plist persistence paths
    "macos_launchagent": re.compile(
        r'(?:~/Library/LaunchAgents/[^\s"\'<>\n]{1,100}\.plist'
        r'|/Library/LaunchAgents/[^\s"\'<>\n]{1,100}\.plist'
        r'|/Library/LaunchDaemons/[^\s"\'<>\n]{1,100}\.plist'
        r'|/System/Library/LaunchAgents/[^\s"\'<>\n]{1,100}\.plist'
        r'|/System/Library/LaunchDaemons/[^\s"\'<>\n]{1,100}\.plist)',
        re.IGNORECASE
    ),
}


# Extensions that commonly appear as false-positive domain suffixes in binary
# artifacts — these are not valid TLDs but may be matched by the domain regex.
_BINARY_ARTIFACT_EXTENSIONS: Set[str] = {
    'dll', 'exe', 'sys', 'inf', 'scr', 'ocx', 'bat', 'pdb', 'drv',
    'cpl', 'msi', 'cat', 'mui', 'nls', 'manifest',
}

# IP networks that are never meaningful external IOCs and should be discarded.
# RFC1918 private ranges are excluded here — they ARE kept (lateral movement
# analysis) but handled separately in extract_and_save_iocs.
_DISCARD_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),          # "This" network
    ipaddress.ip_network('127.0.0.0/8'),         # Loopback
    ipaddress.ip_network('169.254.0.0/16'),      # Link-local
    ipaddress.ip_network('224.0.0.0/4'),         # Multicast
    ipaddress.ip_network('240.0.0.0/4'),         # Reserved
    ipaddress.ip_network('255.255.255.255/32'),  # Broadcast
    ipaddress.ip_network('192.0.2.0/24'),        # TEST-NET-1 (documentation)
    ipaddress.ip_network('198.51.100.0/24'),     # TEST-NET-2 (documentation)
    ipaddress.ip_network('203.0.113.0/24'),      # TEST-NET-3 (documentation)
]

_RFC1918_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
]


def _is_discardable_ip(raw: str) -> bool:
    """Return True if the IP should be silently discarded (never a useful IOC).

    Also discards addresses whose last octet is 0 — these are network/subnet
    addresses (e.g. 120.0.0.0) that appear as version numbers in User-Agent
    strings, build strings, and similar.  No real server host uses x.y.z.0.
    """
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return True
    if addr.packed[-1] == 0:
        return True
    return any(addr in net for net in _DISCARD_NETWORKS)


def _is_private_ip(raw: str) -> bool:
    """Return True if the IP is RFC1918 private (kept as IOC, but marked FP)."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918_NETWORKS)


def extract_valid_ips(text: str):
    """
    Extract IPv4 addresses, discarding loopback / link-local / reserved /
    multicast addresses.  Returns (public_ips, private_ips) as sorted lists.
    Private RFC1918 addresses are returned separately so callers can mark them
    as false positives without sending them to external enrichment APIs.
    """
    public: List[str] = []
    private: List[str] = []
    for raw in set(IOC_PATTERNS["ip"].findall(text)):
        if _is_discardable_ip(raw):
            continue
        if _is_private_ip(raw):
            private.append(raw)
        else:
            public.append(raw)
    return sorted(public), sorted(private)


# --- IOC Extraction Functions ---

def extract_valid_domains(text: str) -> List[str]:
    """Extract domains, validate via tldextract, and filter binary artifacts."""
    matches = IOC_PATTERNS["domain"].finditer(text)
    domains = set()

    for match in matches:
        domain = match.group(0).lower()

        # Drop common binary artifact extensions
        suffix = domain.rsplit('.', 1)[-1]
        if suffix in _BINARY_ARTIFACT_EXTENSIONS:
            continue

        ext = tldextractor(domain)
        if not ext.suffix or not ext.domain:
            continue

        # Drop domains whose registered-domain label is purely numeric —
        # these are version strings like "3.1.0.release", not real hostnames.
        if ext.domain.isdigit():
            continue

        full_domain = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)
        domains.add(full_domain.lower())

    return sorted(domains)


def _read_file_text(path: str) -> str:
    """
    Read a file as text, auto-detecting encoding from its BOM.

    Handles UTF-16 LE/BE (common in PowerShell scripts and some Windows
    artefacts), UTF-32 LE/BE, UTF-8 with BOM, plain UTF-8, and falls back
    to latin-1 for binary/unknown content so no bytes are silently dropped.
    """
    with open(path, 'rb') as fh:
        raw = fh.read()
    # Check 4-byte BOMs before 2-byte ones — UTF-32 LE BOM starts with the
    # same two bytes as UTF-16 LE BOM.
    if raw.startswith(b'\xff\xfe\x00\x00'):
        return raw.decode('utf-32-le', errors='ignore')
    if raw.startswith(b'\x00\x00\xfe\xff'):
        return raw.decode('utf-32-be', errors='ignore')
    if raw.startswith(b'\xff\xfe'):
        return raw.decode('utf-16-le', errors='ignore')
    if raw.startswith(b'\xfe\xff'):
        return raw.decode('utf-16-be', errors='ignore')
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw.decode('utf-8-sig', errors='ignore')
    try:
        return raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return raw.decode('latin-1', errors='ignore')


# Trailing punctuation characters that are never a meaningful part of a URL
# but frequently appear immediately after one in document context.
_URL_TRAILING_JUNK = re.compile(r'[.,;:!?\'")\]}>]+$')


def _clean_urls(raw_urls: List[str]) -> List[str]:
    """Strip trailing document-punctuation from URL matches and deduplicate."""
    seen: Set[str] = set()
    result = []
    for url in raw_urls:
        cleaned = _URL_TRAILING_JUNK.sub('', url)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return sorted(result)


def _domain_from_url(url: str) -> str:
    """Return the registered domain from a URL, or '' on failure."""
    try:
        hostname = urlparse(url).hostname or ''
        ext = tldextractor(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return ''


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract and validate IOCs from a text block."""
    public_ips, private_ips = extract_valid_ips(text)
    return {
        "ip":               public_ips,
        "ip_private":       private_ips,
        "email":            sorted(set(IOC_PATTERNS["email"].findall(text))),
        "url":              _clean_urls(IOC_PATTERNS["url"].findall(text)),
        "domain":           extract_valid_domains(text),
        "bitcoin":          sorted(set(IOC_PATTERNS["bitcoin"].findall(text))),
        "cve":              sorted(set(IOC_PATTERNS["cve"].findall(text))),
        "registry":         sorted(set(IOC_PATTERNS["registry"].findall(text))),
        "named_pipe":       sorted(set(IOC_PATTERNS["named_pipe"].findall(text))),
        "win_persistence":  sorted(set(IOC_PATTERNS["win_persistence"].findall(text))),
        "scheduled_task":   sorted(set(IOC_PATTERNS["scheduled_task"].findall(text))),
        "linux_cron":       sorted(set(IOC_PATTERNS["linux_cron"].findall(text))),
        "systemd_unit":     sorted(set(IOC_PATTERNS["systemd_unit"].findall(text))),
        "macos_launchagent": sorted(set(IOC_PATTERNS["macos_launchagent"].findall(text))),
    }


def format_iocs(iocs: Dict[str, List[str]]) -> str:
    """Human-readable IOC formatter."""
    lines = []
    all_keys = [
        "ip", "ip_private", "domain", "email", "url", "bitcoin", "cve",
        "registry", "named_pipe",
        "win_persistence", "scheduled_task",
        "linux_cron", "systemd_unit", "macos_launchagent",
    ]
    for key in all_keys:
        lines.append(f"{key}:")
        values = iocs.get(key, [])
        if values:
            lines.extend([f"  - {value}" for value in values])
        else:
            lines.append("  - None")
    return "\n".join(lines)


# --- Main Extraction Logic ---

def extract_and_save_iocs(file_path: str) -> str:
    """
    Extract IOCs from file and associate new ones with the DB file record.

    Public IPs and domains are saved normally (true_or_false defaults True)
    and queued for background enrichment.  Private RFC1918 IPs are saved
    immediately as false positives (useful for lateral-movement analysis)
    and are never sent to external enrichment APIs.
    """
    import threading
    from vault.workbench.ioc_enrichment import enrich_iocs_batch  # local import avoids circular deps

    sha256 = os.path.basename(file_path)
    try:
        file = File.objects.get(sha256=sha256)
    except File.DoesNotExist:
        return f"error:\n  - No file found with SHA256: {sha256}"

    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return "error:\n  - Invalid SHA256 format."

    try:
        content = _read_file_text(file_path)
    except FileNotFoundError:
        return "error:\n  - Sample file not found."

    iocs = extract_iocs_from_text(content)
    existing = set(file.iocs.values_list("value", flat=True))

    # IOCs eligible for external enrichment (public IPs + domains)
    to_enrich: List[IOC] = []

    for ioc_type, values in iocs.items():
        for value in values:
            if value in existing:
                continue

            if ioc_type == "ip_private":
                # Private IPs: save as type "ip", pre-mark as false positive.
                ioc, created = IOC.objects.get_or_create(
                    type="ip", value=value,
                    defaults={"true_or_false": False},
                )
                ioc.files.add(file)
            elif ioc_type == "url":
                # URLs inherit true-positive status from their parent domain
                # if that domain is already confirmed malicious in the DB.
                # This avoids the complexity of individual VT URL lookups.
                parent_domain = _domain_from_url(value)
                domain_is_tp = (
                    parent_domain
                    and IOC.objects.filter(
                        type="domain", value=parent_domain, true_or_false=True
                    ).exists()
                )
                ioc, created = IOC.objects.get_or_create(
                    type="url", value=value,
                    defaults={"true_or_false": bool(domain_is_tp)},
                )
                ioc.files.add(file)
            else:
                ioc, created = IOC.objects.get_or_create(type=ioc_type, value=value)
                ioc.files.add(file)
                if created and ioc_type in ("ip", "domain"):
                    to_enrich.append(ioc)

    if to_enrich:
        threading.Thread(
            target=enrich_iocs_batch,
            args=(to_enrich,),
            daemon=True,
        ).start()

    return format_iocs(iocs)
