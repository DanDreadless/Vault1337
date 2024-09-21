import re
from typing import List, Dict

# Define regular expressions for different IOCs
IOC_PATTERNS = {
    # IP Addresses (0.0.0.0 to 255.255.255.255)
    "ip_addresses": re.compile(r'\b(?:(?:2[0-5]{2}|1\d{2}|[1-9]?\d)\.){3}(?:2[0-5]{2}|1\d{2}|[1-9]?\d)\b'),

    # Domains (with strict TLDs)
    "domains": re.compile(
        r'\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:'
        r'ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw|com|org|net|edu|gov|mil|co|io|ai|info|me|name|tech|tv|mobi|asia|jobs|tel|pro|museum|coop|aero|biz)\b',
        re.IGNORECASE
    ),

    # Email Addresses
    "email_addresses": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b', re.IGNORECASE),

    # URLs
    "urls": re.compile(r'\b((?:http|https|ftp)://[^\s/$.?#].[^\s]*)\b', re.IGNORECASE)
}

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    # Use sets to store unique IOCs
    iocs = {key: set(pattern.findall(text)) for key, pattern in IOC_PATTERNS.items()}
    
    # Convert sets back to lists for consistency
    return {key: list(iocs_set) for key, iocs_set in iocs.items()}

def format_iocs(iocs: Dict[str, List[str]]) -> str:
    formatted_iocs = []
    for category, items in iocs.items():
        formatted_iocs.append(f"{category}:")
        if items:
            for item in sorted(items):  # Sorting for consistent output
                formatted_iocs.append(f"  - {item}")
        else:
            formatted_iocs.append("  - None")
    return "\n".join(formatted_iocs)

def extract_iocs_from_file(file_path: str) -> Dict[str, List[str]]:
    # Prevent directory traversal attacks
    sha256_value = file_path.split('/')[-1]
    sha256_pattern = re.compile(r'[^[a-fA-F0-9]{64}$]')
    clean_sha256 = sha256_pattern.sub('', sha256_value)
    file_path = f'vault/samples/{clean_sha256}'
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    iocs = extract_iocs_from_text(content)
    return format_iocs(iocs)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python extract_iocs.py <file_path>")
    else:
        file_path = sys.argv[1]
        print(extract_iocs_from_file(file_path))
