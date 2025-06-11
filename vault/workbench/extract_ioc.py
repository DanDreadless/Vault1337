import os
import re
import time
from typing import List, Dict
from vault.models import File, IOC
import tldextract

# --- Configuration ---

TLD_CACHE_DIR = os.path.join("vault", "static", ".tld_set")
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
                return  # Cache is fresh
        # Update suffix list
        tldextractor.update()
    except Exception as e:
        # Fail silently or log as needed
        pass


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
        "ip": sorted(set(IOC_PATTERNS["ip"].findall(text))),
        "email": sorted(set(IOC_PATTERNS["email"].findall(text))),
        "url": sorted(set(IOC_PATTERNS["url"].findall(text))),
        "domain": extract_valid_domains(text)
    }


def format_iocs(iocs: Dict[str, List[str]]) -> str:
    """Human-readable IOC formatter."""
    lines = []
    for key in ["ip", "domain", "email", "url"]:
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
    try:
        sha256 = file_path.split("/")[-1]
        file = File.objects.get(sha256=sha256)
    except File.DoesNotExist:
        return f"error:\n  - No file found with SHA256: {sha256}"

    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return "error:\n  - Invalid SHA256 format."

    try:
        with open(f"vault/samples/{sha256}", "r", errors="ignore") as f:
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
