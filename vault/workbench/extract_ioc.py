import re
from typing import List, Dict

# Define regular expressions for different IOCs
IOC_PATTERNS = {
    "ip_addresses": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domains": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|co|io|ai|in|au|us|xyz|biz|info|me|name|tech|tv|mobi|asia|jobs|tel|pro|museum|coop|aero|[a-zA-Z]{2})\b', re.IGNORECASE),
    "email_addresses": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
    "urls": re.compile(r'\b((?:http|https|ftp)://[a-zA-Z0-9./?=_-]+)\b', re.IGNORECASE),
}

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    iocs = {key: pattern.findall(text) for key, pattern in IOC_PATTERNS.items()}
    return iocs

def format_iocs(iocs: Dict[str, List[str]]) -> str:
    formatted_iocs = []
    for category, items in iocs.items():
        formatted_iocs.append(f"{category}:")
        for item in items:
            formatted_iocs.append(f"  - {item}")
        if not items:
            formatted_iocs.append("  - None")
    return "\n".join(formatted_iocs)

def extract_iocs_from_file(file_path: str) -> Dict[str, List[str]]:
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    iocs = extract_iocs_from_text(content)
    return format_iocs(iocs)