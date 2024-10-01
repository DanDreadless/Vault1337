import lief
import math
from collections import Counter
from tabulate import tabulate
from datetime import datetime

def calculate_entropy(data):
    """Calculate the entropy of a block of data."""
    if not data:
        return 0

    # Count frequency of each byte
    byte_counts = Counter(data)
    total_bytes = len(data)

    # Calculate the entropy using Shannon's formula
    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy

def lief_parse_subtool(sub_tool, file_path):
    try:
        binary = lief.parse(file_path)
        if binary:
            if sub_tool == 'dos_header':
                pe_header = binary.dos_header
            elif sub_tool == 'rich_header':
                pe_header = binary.rich_header
            elif sub_tool == 'pe_header':
                pe_header = binary.header
            elif sub_tool == 'entrypoint':
                pe_header = binary.entrypoint
            elif sub_tool == 'sections':
                result = []
                headers = ["Name", "Content", "Virtual Address", "Virtual Size", "Offset", "Size"]

                for section in binary.sections:
                    name = section.name
                    contentn = section.content
                    virtual_address = section.virtual_address
                    virtual_size = section.virtual_size
                    offset = section.offset
                    size = section.size
                    result.append([name, contentn, virtual_address, virtual_size, offset, size])
                pe_header= tabulate(result, headers=headers, tablefmt="grid")
            elif sub_tool == 'imports':
                result = []
                # Check if there are any imports
                if not binary.has_imports:
                    pe_header = "No imports found"
                else:
                    pe_header = f"Found {len(binary.imports)} imported libraries\n\n"

                    headers = ["Library", "Function Name", "Address", "Ordinal"]

                    for library in binary.imports:
                        lib_name = library.name
                        for entry in library.entries:
                            func_name = entry.name if entry.name else "N/A"
                            address = entry.iat_address
                            ordinal = entry.ordinal if entry.is_ordinal else "N/A"
                            result.append([lib_name, func_name, address, ordinal])

                    # Print the imports in a tabulated format
                    pe_header += tabulate(result, headers=headers, tablefmt="grid")

            elif sub_tool == 'sigcheck':
                try:
                    pe_header = ""
                    signature = binary.signatures[0]
                    for crt in signature.certificates:
                        pe_header += str(crt) + "\n"

                    # Adding Authenticode Hash
                    authentihash = signature.content_info.digest.hex()
                    pe_header += f"Authenticode Hash: {authentihash}"

                    # Adding Signer Info
                    signer_info = signature.signers[0]
                    pe_header += f"\n\nSigner Info: {signer_info}"
                    verified = binary.verify_signature()
                    pe_header += f"\n\nSignature Verification: {verified}"
                except Exception as e:
                    pe_header = f"Binary is not signed {str(e)}"

            elif sub_tool == 'checkentropy':
                sections_entropy = {}

                for section in pe_file.sections:
                    entropy = calculate_entropy(section.content)
                    sections_entropy[section.name] = entropy
            
                for section_name, entropy in section_entropies.item():
                    pe_header += f"Section: {section_name}, Entropy: {entropy}"
            
            else:
                return f"Error: Invalid subtool: {sub_tool}"
            
            if pe_header:
                return pe_header
            else:
                return f"Failed to retrieve PE header."
        else:
            return f"Error parsing the PE file: {str(file_path)}"
    except Exception as e:
        return f"Error: {str(e)}"
