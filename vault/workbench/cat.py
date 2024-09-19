import sys

def cat_file(file_path):
    encodings = ['utf-8', 'latin1', 'utf-16', 'utf-16le', 'utf-16be']  # List of encodings to try

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as file:
                content = file.read()
                return content  # Return the content if successful
        except UnicodeDecodeError:
            # If decoding fails, try the next encoding
            continue
        except FileNotFoundError:
            return f"Error: File '{file_path}' not found."
        except PermissionError:
            return f"Error: Permission denied to read '{file_path}'."
        except Exception as e:
            return f"Error: {str(e)}"
    
    return "Error: Could not decode the file with any of the specified encodings."