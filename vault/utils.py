import hashlib
import ipaddress
import logging
import mimetypes
import os
import re
import shutil
import socket
import tempfile
from contextlib import contextmanager
from urllib.parse import urlparse

from dotenv import dotenv_values

import requests
import shodan
from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)


# -------------------- FILE HASHING --------------------
# Defined before workbench imports to avoid circular import:
# save_sample, extract, and mail_handler all import hash_sample from here.

def hash_sample(fullpath):
    size = os.stat(fullpath).st_size
    mime = mimetypes.guess_type(fullpath)[0]
    with open(fullpath, 'rb') as f:
        data = f.read()
    md5 = hashlib.md5(data).hexdigest()        # noqa: S324
    sha1 = hashlib.sha1(data).hexdigest()      # noqa: S324
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    magic_byte = data[:2].hex()
    return md5, sha1, sha256, sha512, magic_byte, size, mime


from vault.workbench import (  # noqa: E402  (after hash_sample to break circular import)
    apk_tool,
    decode_tool,
    disassembler,
    display_hex,
    dotnet_tool,
    exif,
    extract,
    extract_ioc,
    lief_parser_tool,
    macho_tool,
    mail_handler,
    ole_tool,
    pdftool,
    pefile_tool,
    runyara,
    save_sample,
    strings,
)


class CustomDateTimeField(models.DateTimeField):
    def value_to_string(self, obj):
        val = self.value_from_object(obj)
        if val:
            return val.replace(microsecond=0).isoformat()
        return ''


# -------------------- VALIDATION --------------------

def validate_sha256(value):
    """Validate that value is a 64-character hex string. Returns the value or raises ValueError."""
    if not re.fullmatch(r'[a-fA-F0-9]{64}', str(value)):
        raise ValueError(f"Invalid SHA256 hash: {value}")
    return str(value)


def is_safe_url(url):
    """
    Validate that a URL is safe to fetch.
    Only allows http/https and rejects private, loopback, link-local,
    reserved, and multicast IP addresses to prevent SSRF.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast):
            return False
        return True
    except Exception:
        return False


def get_file_path_from_sha256(sha256_value):
    try:
        clean_sha256 = validate_sha256(sha256_value)
    except ValueError:
        return None
    file_path = os.path.join(settings.SAMPLE_STORAGE_DIR, clean_sha256)
    return file_path if os.path.exists(file_path) else None


# -------------------- TOOL EXECUTION --------------------

@contextmanager
def _temp_copy(file_path):
    """
    Copy a sample into a temporary directory, yield the temp path to the caller,
    then clean up — so analysis tools never see the real storage path.

    A directory (rather than a bare temp file) is used so that cleanup is done
    with shutil.rmtree(ignore_errors=True).  This is necessary on Windows where
    native analysis libraries (dnfile, pefile, …) may hold the file handle open
    briefly after the tool returns, causing os.unlink() to raise WinError 32.
    rmtree with ignore_errors silently skips locked files; the OS will reclaim
    the temp directory on next reboot at worst.

    /dev/shm is preferred when available (Linux containers) — it is a RAM-backed
    tmpfs, so the copy lands in memory rather than on the overlay filesystem.
    This is a significant speedup in Docker on Windows where both the source
    (bind-mounted Windows path via WSL2) and the default /tmp (overlay fs) are
    slow; writing the working copy to RAM eliminates the second bottleneck.
    """
    _shm = '/dev/shm'
    try:
        tmp_dir = tempfile.mkdtemp(dir=_shm) if os.path.isdir(_shm) else tempfile.mkdtemp()
    except OSError:
        # /dev/shm is full (e.g. large sample exceeds shm_size); fall back to /tmp.
        tmp_dir = tempfile.mkdtemp()
    try:
        tmp_path = os.path.join(tmp_dir, 'sample')
        shutil.copy2(file_path, tmp_path)
        yield tmp_path
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_tool(tool, file_path, password, user):
    if tool == 'hex-viewer':
        with _temp_copy(file_path) as tmp:
            try:
                return display_hex.display_hex_with_ascii(tmp)
            except Exception as e:
                return f"Error getting hex output: {str(e)}"
    elif tool == 'exiftool':
        with _temp_copy(file_path) as tmp:
            try:
                return exif.get_exif_data(tmp)
            except Exception as e:
                return f"Error getting EXIF information: {str(e)}"
    elif tool == 'extract-ioc':
        try:
            return extract_ioc.extract_and_save_iocs(file_path)
        except Exception as e:
            return f"Error extracting IOCs: {str(e)}"
    elif tool == 'run-yara':
        with _temp_copy(file_path) as tmp:
            try:
                return runyara.run_yara(tmp)
            except Exception as e:
                return f"Error running YARA rules: {str(e)}"
    elif tool == 'zip_extractor':
        try:
            return extract.extract_archive(file_path, password, user)
        except Exception as e:
            return f"Error running zip extractor: {str(e)}"
    elif tool == 'disassembler':
        with _temp_copy(file_path) as tmp:
            try:
                return disassembler.disassemble(tmp)
            except Exception as e:
                return f"Error running disassembler: {str(e)}"
    elif tool == 'view-image':
        _MAX_IMAGE_BYTES = 10 * 1024 * 1024
        try:
            file_size = os.path.getsize(file_path)
            if file_size > _MAX_IMAGE_BYTES:
                mb = round(file_size / (1024 * 1024))
                return f"[!] Image too large ({mb} MB) to preview. Maximum is 10 MB."
            import base64
            import io
            from PIL import Image
            with open(file_path, 'rb') as f:
                data = f.read()
            img = Image.open(io.BytesIO(data))
            fmt = (img.format or 'PNG').upper()
            img.close()
            fmt_to_mime = {
                'JPEG': 'image/jpeg', 'PNG': 'image/png', 'GIF': 'image/gif',
                'BMP': 'image/bmp', 'WEBP': 'image/webp', 'TIFF': 'image/tiff',
                'ICO': 'image/x-icon',
            }
            mime_type = fmt_to_mime.get(fmt, 'image/png')
            b64 = base64.b64encode(data).decode('utf-8')
            return f'data:{mime_type};base64,{b64}'
        except Exception as e:
            return f"Error rendering image: {str(e)}"
    else:
        return f"Tool '{tool}' not supported."


def run_sub_tool(tool, sub_tool, file_path):
    with _temp_copy(file_path) as tmp:
        if tool == 'disassembler':
            try:
                return disassembler.disassemble_shellcode(tmp, sub_tool)
            except Exception as e:
                return f"Error running shellcode disassembler: {str(e)}"
        elif tool == 'shellcode':
            try:
                return disassembler.disassemble_shellcode(tmp, sub_tool)
            except Exception as e:
                return f"Error running shellcode disassembler: {str(e)}"
        elif tool == 'lief-parser':
            try:
                return lief_parser_tool.lief_parse_subtool(sub_tool, tmp)
            except Exception as e:
                return f"Error getting PE header information: {str(e)}"
        elif tool == 'oletools':
            try:
                return ole_tool.oletools_subtool_parser(sub_tool, tmp)
            except Exception as e:
                return f"Error checking for macros: {str(e)}"
        elif tool == 'email-parser':
            try:
                return mail_handler.email_subtool_parser(sub_tool, tmp)
            except Exception as e:
                return f"Error parsing email: {str(e)}"
        elif tool == 'strings':
            try:
                return strings.get_strings(tmp, sub_tool)
            except Exception as e:
                return f"Error getting strings: {str(e)}"
        elif tool == 'pdf-parser':
            try:
                return pdftool.extract_forensic_data(tmp, sub_tool)
            except Exception as e:
                return f"Error extracting PDF content: {str(e)}"
        elif tool == 'pefile':
            try:
                return pefile_tool.pefile_subtool(sub_tool, tmp)
            except Exception as e:
                return f"Error running pefile tool: {str(e)}"
        elif tool == 'macho-tool':
            try:
                return macho_tool.macho_subtool(sub_tool, tmp)
            except Exception as e:
                return f"Error running Mach-O tool: {str(e)}"
        elif tool == 'decode':
            try:
                return decode_tool.decode(tmp, sub_tool)
            except Exception as e:
                return f"Error running decode tool: {str(e)}"
        elif tool == 'dotnet':
            try:
                return dotnet_tool.dotnet_subtool(tmp, sub_tool)
            except Exception as e:
                return f"Error running .NET tool: {str(e)}"
        elif tool == 'apk-tool':
            try:
                return apk_tool.apk_subtool(tmp, sub_tool)
            except Exception as e:
                return f"Error running APK tool: {str(e)}"
        else:
            return f"Tool '{tool}' not supported."


# -------------------- API KEY HELPER --------------------

def get_api_key(name):
    """
    Read an API key by name.

    Reads fresh from the project-root .env file on every call so that keys
    saved via the UI are visible to all Gunicorn workers (os.environ is
    process-local and only updated in the single worker that handled the
    save request). Falls back to os.environ to cover keys injected as Docker
    environment variables at container startup.
    """
    env_path = os.path.join(settings.BASE_DIR, '.env')
    if os.path.exists(env_path):
        value = dotenv_values(env_path).get(name)
        if value:
            return value
    return os.getenv(name, '')


# -------------------- EXTERNAL INTEL --------------------

def get_abuseipdb_data(ip):
    abusekey = get_api_key('ABUSEIPDB_KEY')
    if not abusekey or abusekey == 'paste_your_api_key_here':
        return '[!] AbuseIPDB API key not set in .env file'
    headers = {'Key': abusekey, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=10)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        return '[!] Unauthorized: Invalid API key'
    if response.status_code == 403:
        return '[!] Forbidden: Access denied - check your API key'
    if response.status_code == 404:
        return '[?] Not Found: IP address not found'
    return f'[!] Error: {response.status_code} - {response.text}'


def get_spur_data(ip):
    spurkey = get_api_key('SPUR_KEY')
    if not spurkey or spurkey == 'paste_your_api_key_here':
        return '[!] Spur API key not set in .env file'
    headers = {'TOKEN': spurkey}
    response = requests.get(f'https://api.spur.us/v2/context/{ip}', headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        return '[!] Unauthorized: Invalid API key'
    if response.status_code == 403:
        return '[!] Forbidden: Access denied - check your API key'
    if response.status_code == 404:
        return '[?] Not Found: IP address not found'
    return f'[!] Error: {response.status_code} - {response.text}'


def get_vt_data(ip):
    vtkey = get_api_key('VT_KEY')
    if not vtkey or vtkey == 'paste_your_api_key_here':
        return '[!] Virus Total API key not set in .env file'
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": vtkey}
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        return '[!] Unauthorized: Invalid API key'
    if response.status_code == 403:
        return '[!] Forbidden: Access denied - check your API key'
    if response.status_code == 404:
        return '[?] Not Found: IP address not found'
    return f'[!] Error: {response.status_code} - {response.text}'


def get_whois_data(domain):
    """
    Query WHOIS for a domain.  Returns a dict of key fields on success,
    or an error string on failure.  No API key required.
    """
    try:
        import whois as _whois
        r = _whois.whois(domain)
    except Exception as e:
        return f'[!] WHOIS lookup failed: {e}'

    def _fmt(val):
        if val is None:
            return 'N/A'
        if isinstance(val, list):
            # de-duplicate and keep first 5
            seen = []
            for v in val:
                sv = str(v)
                if sv not in seen:
                    seen.append(sv)
            return ', '.join(seen[:5])
        return str(val)

    return {
        'registrar':       _fmt(r.registrar),
        'creation_date':   _fmt(r.creation_date),
        'expiration_date': _fmt(r.expiration_date),
        'updated_date':    _fmt(r.updated_date),
        'name_servers':    _fmt(r.name_servers),
        'status':          _fmt(r.status),
        'registrant_org':  _fmt(getattr(r, 'org', None)),
        'country':         _fmt(getattr(r, 'country', None)),
        'dnssec':          _fmt(getattr(r, 'dnssec', None)),
    }


def get_passive_dns(domain):
    """
    Query VirusTotal for passive DNS resolutions for a domain.
    Returns a list of {ip, last_seen} dicts on success, or an error string.
    Endpoint: GET /api/v3/domains/{domain}/resolutions
    """
    vtkey = get_api_key('VT_KEY')
    if not vtkey or vtkey == 'paste_your_api_key_here':
        return '[!] VirusTotal API key not set in .env file'
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    headers = {"accept": "application/json", "x-apikey": vtkey}
    try:
        response = requests.get(url, headers=headers, timeout=10,
                                params={'limit': 20})
    except requests.RequestException as e:
        return f'[!] Request error: {e}'
    if response.status_code == 200:
        items = response.json().get('data', [])
        results = []
        for item in items:
            attrs = item.get('attributes', {})
            results.append({
                'ip':        attrs.get('ip_address', ''),
                'last_seen': attrs.get('date', ''),
                'resolver':  attrs.get('resolver', ''),
            })
        return results
    if response.status_code == 404:
        return '[?] No passive DNS data found for this domain'
    return f'[!] Error: {response.status_code}'


def get_vt_domain_data(domain):
    """Query VirusTotal for a domain report. Returns parsed JSON dict on success,
    or an error string on failure. Note: different endpoint and response shape
    from get_vt_data() which is IP-only."""
    vtkey = get_api_key('VT_KEY')
    if not vtkey or vtkey == 'paste_your_api_key_here':
        return '[!] Virus Total API key not set in .env file'
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": vtkey}
    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        return f'[!] Request error: {e}'
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        return '[!] Unauthorized: Invalid API key'
    if response.status_code == 403:
        return '[!] Forbidden: Access denied - check your API key'
    if response.status_code == 404:
        return '[?] Not Found: domain not found'
    return f'[!] Error: {response.status_code} - {response.text}'


def get_shodan_data(ip):
    shodankey = get_api_key('SHODAN_KEY')
    if not shodankey or shodankey == 'paste_your_api_key_here':
        return '[!] Shodan API key not set in .env file'
    api = shodan.Shodan(shodankey)
    try:
        return api.host(ip)
    except shodan.APIError as e:
        if 'no information' in str(e).lower():
            return f'[?] Not Found: {ip}'
        if 'invalid' in str(e).lower():
            return '[!] Invalid API Key'
        if 'rate limit' in str(e).lower():
            return '[!] Rate Limit Exceeded'
        return f'[!] Not Found: {e}'


def get_otx_data(indicator: str, ioc_type: str) -> dict | str:
    """
    Query AlienVault OTX for an indicator (ip, domain, or file hash).

    Returns a compact dict on success:
      {'pulse_count': int, 'pulses': [{'name': str, 'tags': [...], 'modified': str}, ...]}
    Returns a string starting with '[!]' or '[?]' on error / not found.
    ioc_type must be one of: 'ip', 'domain', 'hash'
    """
    otx_key = get_api_key('OTX_KEY')
    if not otx_key or otx_key == 'paste_your_api_key_here':
        return '[!] OTX_KEY not set in .env file'

    type_map = {
        'ip':     f'IPv4/{indicator}/general',
        'domain': f'domain/{indicator}/general',
        'hash':   f'file/{indicator}/general',
    }
    if ioc_type not in type_map:
        return f'[!] Unsupported OTX indicator type: {ioc_type}'

    url = f'https://otx.alienvault.com/api/v1/indicators/{type_map[ioc_type]}'
    try:
        resp = requests.get(
            url,
            headers={'X-OTX-API-KEY': otx_key},
            timeout=10,
        )
    except requests.RequestException as exc:
        return f'[!] Request error: {exc}'

    if resp.status_code == 404:
        return '[?] Not found in OTX'
    if resp.status_code == 403:
        return '[!] OTX API key invalid or unauthorised'
    if not resp.ok:
        return f'[!] OTX returned status {resp.status_code}'

    data = resp.json()
    pulse_info = data.get('pulse_info', {})
    pulses_raw = pulse_info.get('pulses', [])
    pulses = [
        {
            'name':     p.get('name', ''),
            'tags':     p.get('tags', [])[:10],
            'modified': p.get('modified', ''),
        }
        for p in pulses_raw[:20]  # cap at 20 pulses in the compact response
    ]
    return {
        'pulse_count': pulse_info.get('count', 0),
        'pulses': pulses,
    }


def fetch_vt_report(sha256):
    """
    Fetch a VirusTotal file report for the given SHA256.
    Returns the parsed JSON attributes dict on success, None on failure.
    Uses get_api_key('VT_KEY') so it works across Gunicorn workers.
    """
    key = get_api_key('VT_KEY')
    if not key or key == 'paste_your_api_key_here':
        return None
    try:
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256}',
            headers={'x-apikey': key},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get('data', {}).get('attributes')
    except Exception as e:
        logger.debug("VT report fetch failed for %s: %s", sha256, e)
    return None
