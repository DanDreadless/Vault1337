import os
import re
import time
import logging
from typing import List, Dict
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
    "ip": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'\b((?:http|https|ftp)://[^\s/$.?#].[^\s]*)\b',
        re.IGNORECASE
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.)+(?P<tld>[a-zA-Z]{2,})\b'
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


# --- IOC Extraction Functions ---

def extract_valid_domains(text: str) -> List[str]:
    """Extract domains and validate using tldextract."""
    matches = IOC_PATTERNS["domain"].finditer(text)
    domains = set()

    for match in matches:
        domain = match.group(0).lower()
        if domain.endswith(".dll"):
            continue

        ext = tldextractor(domain)
        if ext.suffix and ext.domain:
            full_domain = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)
            domains.add(full_domain.lower())

    return sorted(domains)


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract and validate IOCs from a text block."""
    return {
        "ip":               sorted(set(IOC_PATTERNS["ip"].findall(text))),
        "email":            sorted(set(IOC_PATTERNS["email"].findall(text))),
        "url":              sorted(set(IOC_PATTERNS["url"].findall(text))),
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
        "ip", "domain", "email", "url", "bitcoin", "cve",
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
    """Extract IOCs from file and associate new ones with DB file."""
    sha256 = os.path.basename(file_path)
    try:
        file = File.objects.get(sha256=sha256)
    except File.DoesNotExist:
        return f"error:\n  - No file found with SHA256: {sha256}"

    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return "error:\n  - Invalid SHA256 format."

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        return "error:\n  - Sample file not found."

    iocs = extract_iocs_from_text(content)
    existing = set(file.iocs.values_list("value", flat=True))

    for ioc_type, values in iocs.items():
        for value in values:
            if value in existing:
                continue
            ioc, _ = IOC.objects.get_or_create(type=ioc_type, value=value)
            ioc.files.add(file)

    return format_iocs(iocs)
