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
    disassembler,
    display_hex,
    exif,
    extract,
    extract_ioc,
    lief_parser_tool,
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
            val.replace(microsecond=0)
            return val.isoformat()
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
    Copy a sample to an OS temp location, yield the temp path to the caller,
    then clean up — so analysis tools never see the real storage path.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        shutil.copy2(file_path, tmp_path)
        yield tmp_path
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


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
    else:
        return f"Tool '{tool}' not supported."


def run_sub_tool(tool, sub_tool, file_path):
    with _temp_copy(file_path) as tmp:
        if tool == 'lief-parser':
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
    response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
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
    response = requests.get(f'https://api.spur.us/v2/context/{ip}', headers=headers)
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
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        return '[!] Unauthorized: Invalid API key'
    if response.status_code == 403:
        return '[!] Forbidden: Access denied - check your API key'
    if response.status_code == 404:
        return '[?] Not Found: IP address not found'
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
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get('data', {}).get('attributes')
    except Exception:
        pass
    return None
