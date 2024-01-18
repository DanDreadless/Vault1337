import binascii

def display_hex(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            hex_content = binascii.hexlify(content).decode('utf-8')
            return hex_content
    except FileNotFoundError:
         return f"File not found: {file_path}"
    except Exception as e:
        return f"An error occurred: {e}"
