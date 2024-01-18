import binascii

def display_hex_with_ascii(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            hex_content = binascii.hexlify(content).decode('utf-8')
            
            # Split the hex content into pairs of two characters
            hex_pairs = [hex_content[i:i+2] for i in range(0, len(hex_content), 2)]
            
            # Convert hex pairs to ASCII characters
            ascii_characters = ''.join([chr(int(pair, 16)) if int(pair, 16) in range(32, 127) else '.' for pair in hex_pairs])
            
            # Build hex and ASCII content
            result = []
            for i in range(0, len(hex_pairs), 16):
                hex_line = ' '.join(hex_pairs[i:i+16])
                ascii_line = ascii_characters[i:i+16]
                result.append(f"{hex_line.ljust(49)}  {ascii_line}")
                
            return '\n'.join(result)
                
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except Exception as e:
        return f"An error occurred: {e}"
