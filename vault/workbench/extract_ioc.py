import re
from typing import List, Dict
from vault.models import File, IOC  # Adjust the import based on your Django app structure

# Define regular expressions for different IOCs
IOC_PATTERNS = {
    "ip": re.compile(r'\b(?:(?:2[0-5]{2}|1\d{2}|[1-9]?\d)\.){3}(?:2[0-5]{2}|1\d{2}|[1-9]?\d)\b'),
    "domain": re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:'
    r'ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw|com|org|net|edu|gov|mil|info|me|name|tech|mobi|asia|jobs|tel|pro|museum|coop|aero|biz)'
    r'\b(?!\.)',  # Ensures it doesn't match inside other words
    re.IGNORECASE
    ),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b', re.IGNORECASE),
    "url": re.compile(r'\b((?:http|https|ftp)://[^\s/$.?#].[^\s]*)\b', re.IGNORECASE)
}

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from text, ensuring unique and sorted values."""
    iocs = {key: sorted(set(pattern.findall(text))) for key, pattern in IOC_PATTERNS.items()}
    return iocs

def format_iocs(iocs: Dict[str, List[str]]) -> str:
    """Format extracted IOCs into a readable string output."""
    formatted_iocs = []
    for category, items in iocs.items():
        formatted_iocs.append(f"{category}:")
        if items:
            for item in items:
                formatted_iocs.append(f"  - {item}")
        else:
            formatted_iocs.append("  - None")
    return "\n".join(formatted_iocs)

def extract_and_save_iocs(file_path: str) -> Dict[str, List[str]]:
    """Extract IOCs from a file and save only new ones to the database."""
    try:
        sha256 = file_path.split('/')[-1]
        file = File.objects.get(sha256=sha256)
    except File.DoesNotExist:
        return {"error": f"No file found with SHA256: {sha256}"}
    # Prevent directory traversal attacks
    sha256_value = file_path.split('/')[-1]
    sha256_pattern = re.compile(r'[^[a-fA-F0-9]{64}$]')
    clean_sha256 = sha256_pattern.sub('', sha256_value)
    file_path = f'vault/samples/{clean_sha256}'
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        return {"error": "File not found in the vault"}

    iocs = extract_iocs_from_text(content)

    # Fetch existing IOCs linked to the file
    existing_iocs = set(file.iocs.values_list("value", flat=True))

    for ioc_type, ioc_values in iocs.items():
        for ioc_value in ioc_values:
            if not ioc_value or ioc_value in existing_iocs:
                continue  # Skip if IOC is None or already linked to the file
            
            ioc_obj, created = IOC.objects.get_or_create(type=ioc_type, value=ioc_value)
            ioc_obj.files.add(file)  # Associate IOC with the file

    return format_iocs(iocs)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python extract_iocs.py <file_path>")
    else:
        file_path = sys.argv[1]
        print(extract_and_save_iocs(file_path))
