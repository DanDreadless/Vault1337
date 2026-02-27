import cv2
import re
import os
import tempfile
import logging

logger = logging.getLogger(__name__)


def decode_qr(uploaded_file):
    tmp_path = None
    try:
        if not uploaded_file.name.endswith('.png'):
            return "File is not a PNG image."

        fd, tmp_path = tempfile.mkstemp(suffix='.png')
        with os.fdopen(fd, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        image = cv2.imread(tmp_path)
        detector = cv2.QRCodeDetector()
        data, vertices_array, _ = detector.detectAndDecode(image)

        if re.match('https:', data):
            data = re.sub('https:', 'hxxps:', data)
        elif re.match('http:', data):
            data = re.sub('http:', 'hxxp:', data)

        if vertices_array is not None:
            return data
        else:
            return "No QR code found in the image."
    except AttributeError:
        return "No file uploaded."
    except Exception as e:
        logger.exception(e)
        return f"An error occurred: {str(e)}"
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
