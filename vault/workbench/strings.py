# strings.py
# Description: Extract printable strings from a file using user-specified encoding
import os
import re

# Define the maximum file size (in bytes) for parsing
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB, adjust as needed

def get_strings(file_path, encoding):
    try:
        # Check the file size
        file_size = os.path.getsize(file_path)
        convert_size = round(file_size / (1024 * 1024))
        if file_size > MAX_FILE_SIZE:
            return f"Error: File is too large to parse (size: {convert_size}MB, max: 10MB). Try the IOC extraction tool instead."

        all_strings = ""

        with open(file_path, 'rb') as file:
            # Read file in chunks
            chunk_size = 4096
            buffer = b""
            
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break

                buffer += chunk

                # Decode the content using the user-specified encoding
                try:
                    decoded_content = buffer.decode(encoding, errors='ignore')
                except UnicodeDecodeError:
                    return f"Error: Unable to decode file using {encoding} encoding."
                
                # Extract strings using regex (printable ASCII characters)
                matches = re.findall(r'[\x20-\x7E]{4,}', decoded_content)
                all_strings += '\n'.join(matches) + '\n'
                
                # Retain the last few bytes to handle possible multi-byte characters at chunk boundaries
                buffer = buffer[-10:]
                
            return all_strings.strip()  # Remove any trailing newline
            
    except FileNotFoundError:
        return f"Error: File '{file_path}' not found."
    except PermissionError:
        return f"Error: Permission denied to read '{file_path}'."
    except Exception as e:
        return f"Error: {str(e)}"
