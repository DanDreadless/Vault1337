import cv2
import re
import os
# Django Imports
from django.core.files.storage import FileSystemStorage

def decode_qr(uploaded_file):
    try:
        if not uploaded_file.name.endswith('.png'):
            return "File is not a PNG image."
        storage_location =  './vault/working/'
        if not os.path.exists(storage_location):
            os.makedirs(storage_location)
        fs = FileSystemStorage(location=storage_location)
        fs.save(f'{uploaded_file.name}.tmp', uploaded_file)
        full_path = os.path.join(storage_location, f'{uploaded_file.name}.tmp')
        image = cv2.imread(full_path)
        detector = cv2.QRCodeDetector()
        data, vertices_array, _ = detector.detectAndDecode(image)
        os.remove(full_path)  # Clean up the temporary file
        if re.match('https:', data):
            data = re.sub('https:', 'hxxps:', data)
        elif re.match('http:', data):
            data = re.sub('http:', 'hxxp:', data)
        
        if vertices_array is not None:
            return data
        else:
            return "No QR code found in the image."
    except AttributeError:
        os.remove(full_path)  # Clean up the temporary file
        return "No file uploaded."
    except Exception as e:
        os.remove(full_path)  # Clean up the temporary file
        return f"An error occurred: {str(e)}"
