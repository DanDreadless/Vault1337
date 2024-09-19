# strings.py
# Description: Extract printable strings from a file using different encodings
import os
import re

# Define the maximum file size (in bytes) for parsing
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB, adjust as needed

def get_strings(file_path):
    try:
        # Check the file size
        file_size = os.path.getsize(file_path)
        convert_size = round(file_size / (1024 * 1024))
        if file_size > MAX_FILE_SIZE:
            return f"Error: File is too large to parse (size: {convert_size}MB, max: 10MB). Try the IOC extraction tool instead."

        all_strings = ""
        encodings = ['utf-8', 'latin1', 'utf-16le']  # Added utf-16le encoding
        
        with open(file_path, 'rb') as file:
            # Read file in chunks
            chunk_size = 4096
            buffer = b""
            
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break

                buffer += chunk
                decoded_content = None

                # Try different encodings
                for encoding in encodings:
                    try:
                        decoded_content = buffer.decode(encoding, errors='ignore')
                        break
                    except UnicodeDecodeError:
                        continue

                if decoded_content is None:
                    # Fallback to a default encoding if all others fail
                    decoded_content = buffer.decode('latin1', errors='ignore')

                # Extract strings using regex (account for multi-byte characters)
                # \x20-\x7E are printable ASCII characters; however, for UTF-16LE, you need to adjust to consider two-byte sequences.
                if 'utf-16' in encoding:
                    matches = re.findall(r'[\x20-\x7E]{2,}', decoded_content)
                else:
                    matches = re.findall(r'[\x20-\x7E]{4,}', decoded_content)
                    
                all_strings += '\n'.join(matches) + '\n'
                
                # Retain the last few bytes to handle possible multi-byte characters at chunk boundaries
                buffer = buffer[-10:]
                
            return all_strings.strip()  # Remove any trailing newline
            
    except Exception as e:
        return f"Error: {str(e)}"
