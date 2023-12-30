# strings.py
import string

def get_strings(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            # Decode the content assuming it's in UTF-8, adjust as needed
            decoded_content = content.decode('utf-8', errors='ignore')
            
            # Filter printable characters (strings)
            # deepcode ignore useCompehensions: <please specify a reason of ignoring this>
            printable_strings = ''.join(filter(lambda x: x in string.printable, decoded_content))
            return printable_strings
    except Exception as e:
        return f"Error: {str(e)}"
