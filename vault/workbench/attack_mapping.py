"""
MITRE ATT&CK technique mapper.

Scans saved AnalysisResult outputs for a File and returns a list of
matched techniques. Results are stored in File.attack_mapping as:

    [
        {
            "id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion",
            "indicators": ["VirtualAllocEx", "WriteProcessMemory"]
        },
        ...
    ]

Four mapping sources are used in combination:
  1. Regex patterns against saved AnalysisResult tool output text
  2. IOC type → technique mapping from linked IOC objects
  3. VirusTotal threat classification (popular_threat_category / suggested_threat_label)
  4. MalwareBazaar tags / signature
"""

import logging
import re

from vault.models import AnalysisResult, File

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Technique definitions
# Each entry: technique_id → {name, tactic, patterns}
# Patterns are matched case-insensitively against concatenated tool output.
# Use word boundaries (\b) where needed to avoid substring false positives.
# ---------------------------------------------------------------------------

TECHNIQUE_MAP: dict[str, dict] = {

    # ── Initial Access ─────────────────────────────────────────────────────
    'T1566': {
        'name': 'Phishing',
        'tactic': 'Initial Access',
        'patterns': [
            # Email structure markers (from email parser tool output)
            r'\bFrom:\s', r'\bSubject:\s', r'MIME-Version:', r'Return-Path:',
            r'Content-Type:\s*multipart', r'X-Mailer:', r'Received:\s*from',
            # HTML phishing page patterns
            r'password.*input', r'credential.*form', r'login.*form',
            r'verify.*account', r'confirm.*identity',
            # Generic phishing indicators
            r'\bphish', r'credential.?harvest',
        ],
    },
    'T1566.001': {
        'name': 'Spearphishing Attachment',
        'tactic': 'Initial Access',
        'patterns': [
            # OLETools / macro autoexec triggers
            r'\bAutoOpen\b', r'\bAutoClose\b', r'\bAutoExec\b',
            r'\bAuto_Open\b', r'\bAuto_Close\b',
            r'\bDocument_Open\b', r'\bWorkbook_Open\b',
            r'\bDocument_Close\b', r'\bWorkbook_Close\b',
            r'Doc_AutoOpen', r'Doc_Macro',
            # OLE macro presence
            r'Macros.*:\s*True', r'olevba.*AutoExec', r'VBA.*macro',
            r'OLEVBA', r'Macro.*found',
            # PDF with embedded executables / scripts
            r'/EmbeddedFile', r'Embedded.*file.*found',
        ],
    },
    'T1566.002': {
        'name': 'Spearphishing Link',
        'tactic': 'Initial Access',
        'patterns': [
            # HTML link patterns
            r'<a\s[^>]*href\s*=', r'href\s*=\s*["\']https?://',
            # Email body URL extraction (from email parser URL Extractor output)
            r'https?://[^\s<>"]+', r'URL.*extracted.*from.*body',
            # Redirect / click-here lures
            r'click\s*here', r'url.*redirect', r'Redirect.*URL',
            r'DocuSign', r'SharePoint.*link', r'OneDrive.*link',
        ],
    },

    # ── Execution ──────────────────────────────────────────────────────────
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
        'patterns': [
            r'cmd\.exe', r'powershell', r'WScript', r'CScript',
            r'ShellExecuteA?W?', r'WinExec',
            r'Script_PowerShell', r'Doc_Macro',
            r'\bsystem\b', r'\bpopen\b', r'\bexecv\b', r'\bexecve\b',
            r'\bexecl\b', r'\bsh\b.*\bshell\b',
        ],
    },
    'T1106': {
        'name': 'Native API',
        'tactic': 'Execution',
        'patterns': [
            r'NtCreateProcess', r'NtCreateUserProcess', r'ZwCreateProcess',
            r'NtAllocateVirtualMemory', r'ZwAllocateVirtualMemory',
            r'NtCreateSection', r'ZwCreateSection',
        ],
    },
    'T1129': {
        'name': 'Shared Modules',
        'tactic': 'Execution',
        'patterns': [
            r'LoadLibraryA?W?', r'LoadLibraryExA?W?',
            r'GetProcAddress',
        ],
    },
    'T1204': {
        'name': 'User Execution',
        'tactic': 'Execution',
        'patterns': [
            # Macro auto-run on document open (user opens = user executes)
            r'\bAutoOpen\b', r'\bAutoExec\b', r'\bAuto_Open\b',
            r'\bDocument_Open\b', r'\bWorkbook_Open\b',
            r'Doc_AutoOpen', r'Shell.*autorun',
            # Script auto-execution patterns
            r'wscript\.shell', r'\.Run\(', r'\.Exec\(',
        ],
    },
    'T1203': {
        'name': 'Exploitation for Client Execution',
        'tactic': 'Execution',
        'patterns': [
            # CVE references in tool output (strings, PDF metadata, etc.)
            r'CVE-\d{4}-\d+',
            # Exploit technique indicators
            r'\bshellcode\b', r'\bexploit\b', r'heap\s*spray',
            r'use.after.free', r'buffer\s*overflow', r'ROP\s*chain',
            r'stack\s*pivot', r'return.oriented',
            # PDF exploit patterns (PDF parser output)
            r'/JavaScript\b', r'/JS\b', r'PDF.*JavaScript',
        ],
    },

    # ── Persistence ────────────────────────────────────────────────────────
    'T1053': {
        'name': 'Scheduled Task/Job',
        'tactic': 'Persistence',
        'patterns': [
            r'schtasks\s+/(?:Create|Run|Delete|Query)',
            r'New-ScheduledTask', r'Register-ScheduledTask', r'Set-ScheduledTask',
            r'ITaskService', r'ITaskScheduler',
            r'/etc/cron', r'crontab\b',
            r'at\.exe',
        ],
    },
    'T1547': {
        'name': 'Boot or Logon Autostart Execution',
        'tactic': 'Persistence',
        'patterns': [
            r'CurrentVersion\\Run',
            r'MacOS_LaunchAgent',
        ],
    },
    'T1543': {
        'name': 'Create or Modify System Process',
        'tactic': 'Persistence',
        'patterns': [
            r'CreateServiceA?W?', r'OpenSCManagerA?W?', r'StartServiceA?W?',
            r'ChangeServiceConfig',
        ],
    },

    # ── Privilege Escalation ───────────────────────────────────────────────
    'T1548': {
        'name': 'Abuse Elevation Control Mechanism',
        'tactic': 'Privilege Escalation',
        'patterns': [
            r'setuid\b', r'setgid\b', r'chmod.*[0-7]777',
            r'AdjustTokenPrivileges',
            r'\bsudo\b',
        ],
    },

    # ── Defense Evasion ────────────────────────────────────────────────────
    'T1055': {
        'name': 'Process Injection',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'VirtualAllocEx', r'WriteProcessMemory', r'CreateRemoteThread',
            r'NtCreateThreadEx', r'RtlCreateUserThread', r'QueueUserAPC',
            r'SetThreadContext', r'NtMapViewOfSection', r'NtWriteVirtualMemory',
            r'Win_Process_Injection',
            r'\bptrace\b', r'process_vm_readv', r'process_vm_writev',
        ],
    },
    'T1027': {
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'Packer.*detected', r'packer.*detected', r'packer.*found',
            r'\bUPX\b', r'\bMPRESS\b', r'\bASPack\b', r'\bThemida\b',
            r'Win_Packer', r'high.*entropy.*section', r'packed.*binary',
            r'elf.*packer', r'obfuscator.*detected',
            r'ConfuserEx', r'SmartAssembly', r'Dotfuscator', r'KoiVM', r'Eazfuscator',
            r'single.char.*type.*ratio',
            # Script obfuscation
            r'base64.*decode.*eval', r'chr\(\d+\)\s*&', r'fromcharcode',
            r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}',  # hex-escaped strings
        ],
    },
    'T1497': {
        'name': 'Virtualization/Sandbox Evasion',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'Win_AntiVM', r'Win_AntiDebug',
            r'\bVMware\b', r'\bVirtualBox\b', r'\bVBOX\b', r'\bQEMU\b',
            r'\bXen\b', r'\bParallels\b', r'vmtoolsd', r'vboxservice',
            r'IsDebuggerPresent', r'CheckRemoteDebuggerPresent',
            r'NtQueryInformationProcess', r'OutputDebugString',
            r'anti.?vm', r'anti.?debug',
        ],
    },
    'T1140': {
        'name': 'Deobfuscate/Decode Files or Information',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'CryptDecrypt', r'CryptImportKey', r'CryptAcquireContext',
            r'BCryptDecrypt', r'RtlDecompressBuffer',
        ],
    },
    'T1070': {
        'name': 'Indicator Removal',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'DeleteFileA?W?', r'ClearEventLog', r'wevtutil.*cl',
            r'\bunlink\b', r'remove.*log',
        ],
    },
    'T1574': {
        'name': 'Hijack Execution Flow',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'LD_PRELOAD', r'Linux_ELF_LD_Preload',
            r'\bdlopen\b', r'\bdlsym\b',
        ],
    },
    'T1562': {
        'name': 'Impair Defenses',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'AdjustTokenPrivileges',
            r'netsh.*firewall', r'netsh.*advfirewall',
            r'DisableAV', r'TerminateProcess.*(?:antivirus|defender|av)',
        ],
    },
    'T1014': {
        'name': 'Rootkit',
        'tactic': 'Defense Evasion',
        'patterns': [
            r'\brootkit\b', r'SSDT.*hook', r'hook.*syscall',
            r'DKOM', r'direct.*kernel.*object', r'hide.*process',
            r'kernel.*hook', r'\bIDT\b.*hook',
        ],
    },

    # ── Credential Access ──────────────────────────────────────────────────
    'T1003': {
        'name': 'OS Credential Dumping',
        'tactic': 'Credential Access',
        'patterns': [
            r'\blsass\b', r'MiniDumpWriteDump',
            r'SamEnumerateUsersInDomain', r'LsaEnumerateLogonSessions',
            r'mimikatz',
        ],
    },

    # ── Discovery ──────────────────────────────────────────────────────────
    'T1057': {
        'name': 'Process Discovery',
        'tactic': 'Discovery',
        'patterns': [
            r'CreateToolhelp32Snapshot', r'Process32First', r'Process32Next',
            r'EnumProcesses', r'NtQuerySystemInformation',
        ],
    },
    'T1082': {
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
        'patterns': [
            r'GetSystemInfo', r'GetComputerNameA?W?', r'GetVersionEx',
            r'RtlGetVersion',
            r'\buname\b',
        ],
    },
    'T1083': {
        'name': 'File and Directory Discovery',
        'tactic': 'Discovery',
        'patterns': [
            r'FindFirstFileA?W?', r'FindNextFileA?W?',
            r'\bopendir\b', r'\breaddir\b',
        ],
    },
    'T1012': {
        'name': 'Query Registry',
        'tactic': 'Discovery',
        'patterns': [
            r'RegOpenKeyA?W?', r'RegQueryValueA?W?', r'RegEnumKeyA?W?',
            r'HKEY_LOCAL_MACHINE', r'HKEY_CURRENT_USER',
        ],
    },
    'T1016': {
        'name': 'System Network Configuration Discovery',
        'tactic': 'Discovery',
        'patterns': [
            r'GetAdaptersInfo', r'GetAdaptersAddresses',
            r'\bgetifaddrs\b', r'\bif_nameindex\b',
        ],
    },

    # ── Lateral Movement ───────────────────────────────────────────────────
    'T1021': {
        'name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'patterns': [
            r'WNetAddConnection', r'WNetOpenEnum',
            r'OpenSCManagerA?W?',
        ],
    },
    'T1091': {
        'name': 'Replication Through Removable Media',
        'tactic': 'Lateral Movement',
        'patterns': [
            r'\bAutorun\.inf\b', r'autorun.*usb', r'usb.*spread',
            r'removable.*media', r'GetDriveType.*REMOVABLE',
        ],
    },

    # ── Collection ─────────────────────────────────────────────────────────
    'T1056': {
        'name': 'Input Capture',
        'tactic': 'Collection',
        'patterns': [
            r'SetWindowsHookEx', r'GetAsyncKeyState', r'GetKeyState',
            r'\bkeylog',
        ],
    },
    'T1560': {
        'name': 'Archive Collected Data',
        'tactic': 'Collection',
        'patterns': [
            r'minizip', r'ZipAdd', r'deflateInit',
        ],
    },

    # ── Command and Control ────────────────────────────────────────────────
    'T1071': {
        'name': 'Application Layer Protocol',
        'tactic': 'Command and Control',
        'patterns': [
            r'WinHttpOpen', r'WinHttpSendRequest', r'InternetOpenA?W?',
            r'InternetConnectA?W?', r'HttpSendRequestA?W?',
            r'\bcurl_easy_init\b', r'\bsocket\b', r'\bconnect\b',
            r'Network.*Functions',
        ],
    },
    'T1095': {
        'name': 'Non-Application Layer Protocol',
        'tactic': 'Command and Control',
        'patterns': [
            r'SOCK_RAW', r'IPPROTO_RAW',
            r'pcap_open',
        ],
    },
    'T1105': {
        'name': 'Ingress Tool Transfer',
        'tactic': 'Command and Control',
        'patterns': [
            r'URLDownloadToFileA?W?', r'DownloadFile',
            r'bitsadmin.*transfer', r'bitsadmin.*/transfer',
            r'WinHttpDownload', r'InternetReadFile',
            r'Invoke-WebRequest', r'wget\s+https?', r'curl\s+-[sL]',
        ],
    },
    'T1132': {
        'name': 'Data Encoding',
        'tactic': 'Command and Control',
        'patterns': [
            r'FromBase64String', r'\[Convert\]::FromBase64',
            r'base64_decode', r'base64_encode',
            r'atob\(', r'btoa\(',
        ],
    },

    # ── Impact ─────────────────────────────────────────────────────────────
    'T1486': {
        'name': 'Data Encrypted for Impact',
        'tactic': 'Impact',
        'patterns': [
            r'Win_Ransomware',
            r'CryptEncrypt', r'BCryptEncrypt',
            r'\bransom\b', r'YOUR_FILES.*ENCRYPT',
            r'pay.*bitcoin', r'decrypt.*key.*send',
        ],
    },
    'T1485': {
        'name': 'Data Destruction',
        'tactic': 'Impact',
        'patterns': [
            r'DeviceIoControl.*FORMAT', r'ZeroMemory.*disk',
            r'\bshred\b', r'secure_delete',
        ],
    },
    'T1496': {
        'name': 'Resource Hijacking',
        'tactic': 'Impact',
        'patterns': [
            r'\bxmrig\b', r'stratum\+tcp', r'\bmonero\b', r'cryptominer',
            r'coinhive', r'mining.*pool', r'XMRig',
            r'niceHash', r'minergate',
        ],
    },
}

# Tactic canonical ordering for display
TACTIC_ORDER = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Impact',
]


# ---------------------------------------------------------------------------
# Source 2: Direct mapping from IOC type → (technique_id, indicator_label)
# ---------------------------------------------------------------------------
IOC_TYPE_TECHNIQUES: dict[str, tuple[str, str]] = {
    'scheduled_task':   ('T1053',  'Scheduled task IOC extracted'),
    'linux_cron':       ('T1053',  'Cron job IOC extracted'),
    'win_persistence':  ('T1547',  'Windows persistence IOC extracted'),
    'systemd_unit':     ('T1543',  'Systemd unit IOC extracted'),
    'macos_launchagent':('T1547',  'macOS LaunchAgent IOC extracted'),
    'named_pipe':       ('T1055',  'Named pipe / mutex IOC extracted'),
    # Network / phishing indicators
    'url':              ('T1071',  'URL IOC extracted — network communication indicator'),
    'email':            ('T1566',  'Email address IOC extracted — phishing context'),
    # Exploitation
    'cve':              ('T1203',  'CVE IOC extracted — exploitation indicator'),
    # Ransomware / financial
    'bitcoin':          ('T1486',  'Bitcoin address IOC extracted — ransomware indicator'),
}


# ---------------------------------------------------------------------------
# Source 3: VirusTotal threat classification → technique
# Matched against popular_threat_category values and suggested_threat_label.
# ---------------------------------------------------------------------------

# Maps a VT popular_threat_category 'value' string (lowercase) → technique
VT_CATEGORY_TECHNIQUES: dict[str, tuple[str, str]] = {
    'phishing':      ('T1566', 'VT threat category: phishing'),
    'trojan':        ('T1059', 'VT threat category: trojan'),
    'ransomware':    ('T1486', 'VT threat category: ransomware'),
    'exploit':       ('T1203', 'VT threat category: exploit'),
    'backdoor':      ('T1071', 'VT threat category: backdoor'),
    'downloader':    ('T1105', 'VT threat category: downloader'),
    'dropper':       ('T1105', 'VT threat category: dropper'),
    'infostealer':   ('T1056', 'VT threat category: infostealer'),
    'keylogger':     ('T1056', 'VT threat category: keylogger'),
    'banker':        ('T1056', 'VT threat category: banker'),
    'cryptominer':   ('T1496', 'VT threat category: cryptominer'),
    'miner':         ('T1496', 'VT threat category: miner'),
    'rootkit':       ('T1014', 'VT threat category: rootkit'),
    'rat':           ('T1071', 'VT threat category: remote access trojan'),
    'spyware':       ('T1056', 'VT threat category: spyware'),
    'worm':          ('T1091', 'VT threat category: worm'),
}

# Regex patterns matched against the VT suggested_threat_label string.
# Each entry: (pattern, technique_id, label_template)
VT_LABEL_PATTERNS: list[tuple[str, str, str]] = [
    (r'phish',              'T1566',     'VT threat label: {}'),
    (r'spearphish',         'T1566.001', 'VT threat label: {}'),
    (r'ransom',             'T1486',     'VT threat label: {}'),
    (r'miner|cryptominer',  'T1496',     'VT threat label: {}'),
    (r'banker|banking',     'T1056',     'VT threat label: {}'),
    (r'stealer|infostealer','T1056',     'VT threat label: {}'),
    (r'\brat\b',            'T1071',     'VT threat label: {}'),
    (r'backdoor',           'T1071',     'VT threat label: {}'),
    (r'exploit',            'T1203',     'VT threat label: {}'),
    (r'dropper|loader',     'T1105',     'VT threat label: {}'),
    (r'downloader',         'T1105',     'VT threat label: {}'),
    (r'rootkit',            'T1014',     'VT threat label: {}'),
    (r'worm',               'T1091',     'VT threat label: {}'),
    (r'keylogger|keylog',   'T1056',     'VT threat label: {}'),
    (r'spyware',            'T1056',     'VT threat label: {}'),
]


# ---------------------------------------------------------------------------
# Source 4: MalwareBazaar tags / signature → technique
# Matched case-insensitively against MB tag strings and signature field.
# ---------------------------------------------------------------------------

MB_TAG_TECHNIQUES: dict[str, tuple[str, str]] = {
    'phishing':       ('T1566',     'MalwareBazaar tag: phishing'),
    'spearphishing':  ('T1566.001', 'MalwareBazaar tag: spearphishing'),
    'ransomware':     ('T1486',     'MalwareBazaar tag: ransomware'),
    'backdoor':       ('T1071',     'MalwareBazaar tag: backdoor'),
    'downloader':     ('T1105',     'MalwareBazaar tag: downloader'),
    'dropper':        ('T1105',     'MalwareBazaar tag: dropper'),
    'keylogger':      ('T1056',     'MalwareBazaar tag: keylogger'),
    'miner':          ('T1496',     'MalwareBazaar tag: miner'),
    'cryptominer':    ('T1496',     'MalwareBazaar tag: cryptominer'),
    'rootkit':        ('T1014',     'MalwareBazaar tag: rootkit'),
    'exploit':        ('T1203',     'MalwareBazaar tag: exploit'),
    'worm':           ('T1091',     'MalwareBazaar tag: worm'),
    'stealer':        ('T1056',     'MalwareBazaar tag: stealer'),
    'infostealer':    ('T1056',     'MalwareBazaar tag: infostealer'),
    'rat':            ('T1071',     'MalwareBazaar tag: remote access trojan'),
    'spyware':        ('T1056',     'MalwareBazaar tag: spyware'),
    'banker':         ('T1056',     'MalwareBazaar tag: banker'),
    'trojan':         ('T1059',     'MalwareBazaar tag: trojan'),
}

# Regex patterns matched against the MB signature string (malware family name).
MB_SIGNATURE_PATTERNS: list[tuple[str, str, str]] = [
    (r'phish',              'T1566',     'MalwareBazaar signature: {}'),
    (r'ransom|crypt(?!o)',  'T1486',     'MalwareBazaar signature: {}'),
    (r'miner|xmrig',        'T1496',     'MalwareBazaar signature: {}'),
    (r'banker|banking|zeus|emotet|trickbot|qakbot|dridex', 'T1056', 'MalwareBazaar signature: {}'),
    (r'stealer|formgrab',   'T1056',     'MalwareBazaar signature: {}'),
    (r'\brat\b|remcos|njrat|darkcomet',  'T1071', 'MalwareBazaar signature: {}'),
    (r'backdoor',           'T1071',     'MalwareBazaar signature: {}'),
    (r'exploit',            'T1203',     'MalwareBazaar signature: {}'),
    (r'dropper|loader|bazar|bumblebee',  'T1105', 'MalwareBazaar signature: {}'),
    (r'rootkit',            'T1014',     'MalwareBazaar signature: {}'),
    (r'worm',               'T1091',     'MalwareBazaar signature: {}'),
]


def map_attack_techniques(file_instance: File) -> list[dict]:
    """
    Map MITRE ATT&CK techniques for a file by scanning four sources:

    1. Saved AnalysisResult output text (tool run outputs)
    2. IOC objects linked to the file (type-based direct mapping)
    3. VirusTotal threat classification data stored on the file
    4. MalwareBazaar tags and signature stored on the file

    Returns a deduplicated list sorted by tactic then technique ID.
    Each dict: {"id": "T1055", "name": "...", "tactic": "...", "indicators": [...]}
    """
    # technique_id → set of indicator strings
    hits: dict[str, set[str]] = {}

    # ── Source 1: AnalysisResult text ──────────────────────────────────────
    # Exclude extract-ioc output — it contains IOC type section headers
    # (e.g. "scheduled_task:", "macos_launchagent:") that match technique
    # patterns even when no IOCs of that type were found. IOC-based mapping
    # is handled correctly by Source 2 (linked IOC objects) instead.
    results = (
        AnalysisResult.objects
        .filter(file=file_instance)
        .exclude(tool='extract-ioc')
        .values_list('output', flat=True)
    )
    combined = '\n'.join(results)

    for tid, info in TECHNIQUE_MAP.items():
        for pattern in info['patterns']:
            try:
                found = re.findall(pattern, combined, re.IGNORECASE)
                for h in found:
                    norm = re.sub(r'\s+', ' ', h.strip())
                    if norm:
                        hits.setdefault(tid, set()).add(norm)
            except re.error:
                logger.warning('attack_mapping: bad regex %r for %s', pattern, tid)

    # ── Source 2: linked IOC types ─────────────────────────────────────────
    ioc_types = (
        file_instance.iocs
        .values_list('type', flat=True)
        .distinct()
    )
    for ioc_type in ioc_types:
        mapping = IOC_TYPE_TECHNIQUES.get(ioc_type)
        if mapping:
            tid, label = mapping
            hits.setdefault(tid, set()).add(label)

    # ── Source 3: VirusTotal threat classification ──────────────────────────
    vt_data = getattr(file_instance, 'vt_data', None) or {}
    if isinstance(vt_data, dict):
        classification = (vt_data.get('popular_threat_classification') or {})

        # 3a. popular_threat_category list
        for cat_entry in (classification.get('popular_threat_category') or []):
            cat_value = (cat_entry.get('value') or '').lower()
            mapping = VT_CATEGORY_TECHNIQUES.get(cat_value)
            if mapping:
                tid, label = mapping
                hits.setdefault(tid, set()).add(label)

        # 3b. suggested_threat_label free-text match
        threat_label = (classification.get('suggested_threat_label') or '').lower()
        if threat_label:
            for pattern, tid, label_tmpl in VT_LABEL_PATTERNS:
                try:
                    if re.search(pattern, threat_label, re.IGNORECASE):
                        hits.setdefault(tid, set()).add(label_tmpl.format(threat_label))
                except re.error:
                    logger.warning('attack_mapping: bad VT label pattern %r', pattern)

        # 3c. VT file tags (e.g. "macro", "exploit", "pdf-exploit")
        vt_tags = [str(t).lower() for t in (vt_data.get('tags') or [])]
        if 'macro' in vt_tags or 'macros' in vt_tags:
            hits.setdefault('T1566.001', set()).add('VT tag: macro')
        if any('exploit' in t for t in vt_tags):
            hits.setdefault('T1203', set()).add('VT tag: ' + next(t for t in vt_tags if 'exploit' in t))
        if any('phish' in t for t in vt_tags):
            hits.setdefault('T1566', set()).add('VT tag: ' + next(t for t in vt_tags if 'phish' in t))

    # ── Source 4: MalwareBazaar tags + signature ────────────────────────────
    mb_data = getattr(file_instance, 'mb_data', None) or {}
    if isinstance(mb_data, dict):
        # 4a. MB tags list
        for tag in (mb_data.get('tags') or []):
            key = tag.strip().lower()
            mapping = MB_TAG_TECHNIQUES.get(key)
            if mapping:
                tid, label = mapping
                hits.setdefault(tid, set()).add(label)
            else:
                # Substring fallback for composite tags like "Phishing-Excel"
                for keyword, (tid, label) in MB_TAG_TECHNIQUES.items():
                    if keyword in key:
                        hits.setdefault(tid, set()).add(f'MalwareBazaar tag: {tag}')
                        break

        # 4b. MB signature (malware family name)
        signature = (mb_data.get('signature') or '').strip()
        if signature:
            for pattern, tid, label_tmpl in MB_SIGNATURE_PATTERNS:
                try:
                    if re.search(pattern, signature, re.IGNORECASE):
                        hits.setdefault(tid, set()).add(label_tmpl.format(signature))
                except re.error:
                    logger.warning('attack_mapping: bad MB signature pattern %r', pattern)

    if not hits:
        logger.info('attack_mapping: file %d — no techniques matched', file_instance.pk)
        return []

    # ── Build result list ───────────────────────────────────────────────────
    matched = []
    for tid, indicators in hits.items():
        info = TECHNIQUE_MAP.get(tid)
        if not info:
            continue
        matched.append({
            'id': tid,
            'name': info['name'],
            'tactic': info['tactic'],
            'indicators': sorted(indicators)[:10],
        })

    tactic_idx = {t: i for i, t in enumerate(TACTIC_ORDER)}
    matched.sort(key=lambda t: (tactic_idx.get(t['tactic'], 99), t['id']))

    logger.info('attack_mapping: file %d — %d techniques matched', file_instance.pk, len(matched))
    return matched
