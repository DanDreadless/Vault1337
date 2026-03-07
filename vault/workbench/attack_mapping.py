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

    # ── Persistence ────────────────────────────────────────────────────────
    'T1053': {
        'name': 'Scheduled Task/Job',
        'tactic': 'Persistence',
        'patterns': [
            # Match actual schtasks usage in strings/tool output, not the IOC section header.
            # IOC type 'scheduled_task' is handled by IOC_TYPE_TECHNIQUES (Source 2).
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
            # Registry run key usage in strings/tool output.
            # IOC types 'win_persistence', 'systemd_unit', 'macos_launchagent'
            # are handled by IOC_TYPE_TECHNIQUES (Source 2).
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

    # ── Lateral Movement ───────────────────────────────────────────────────
    'T1021': {
        'name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'patterns': [
            r'WNetAddConnection', r'WNetOpenEnum',
            r'OpenSCManagerA?W?',
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
}

# Tactic canonical ordering for display
TACTIC_ORDER = [
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


# Direct mapping from IOC type → (technique_id, indicator_label)
# Used to match techniques from the file's linked IOC objects,
# independently of whether a tool output was saved.
IOC_TYPE_TECHNIQUES: dict[str, tuple[str, str]] = {
    'scheduled_task':   ('T1053', 'Scheduled task IOC extracted'),
    'linux_cron':       ('T1053', 'Cron job IOC extracted'),
    'win_persistence':  ('T1547', 'Windows persistence IOC extracted'),
    'systemd_unit':     ('T1543', 'Systemd unit IOC extracted'),
    'macos_launchagent':('T1547', 'macOS LaunchAgent IOC extracted'),
    'named_pipe':       ('T1055', 'Named pipe / mutex IOC extracted'),
}


def map_attack_techniques(file_instance: File) -> list[dict]:
    """
    Map MITRE ATT&CK techniques for a file by scanning two sources:

    1. Saved AnalysisResult output text (tool run outputs)
    2. IOC objects linked to the file (type-based direct mapping)

    Returns a deduplicated list sorted by tactic then technique ID.
    Each dict: {"id": "T1055", "name": "...", "tactic": "...", "indicators": [...]}
    """
    # ── Source 1: AnalysisResult text ────────────────────────────────────────
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

    # technique_id → set of indicator strings
    hits: dict[str, set[str]] = {}

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

    # ── Source 2: linked IOC types ────────────────────────────────────────────
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

    if not hits:
        logger.info('attack_mapping: file %d — no techniques matched', file_instance.pk)
        return []

    # ── Build result list ─────────────────────────────────────────────────────
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
