import os
import hashlib
import mimetypes
from django.db import models

def hash_sample(fullpath):
    fullpath = fullpath
    size = os.stat(fullpath).st_size
    mime = mimetypes.guess_type(fullpath)[0]

    # Open the file in binary mode
    with open(fullpath, 'rb') as file:
        file_content = file.read()
        # file deepcode ignore InsecureHash: <please specify a reason of ignoring this>
        md5 = hashlib.md5(file_content).hexdigest()
        sha1 = hashlib.sha1(file_content).hexdigest()
        sha256 = hashlib.sha256(file_content).hexdigest()
        sha512 = hashlib.sha512(file_content).hexdigest()
        magic_byte = file_content[:4].hex()
    
    return md5, sha1, sha256, sha512, magic_byte, size, mime

class CustomDateTimeField(models.DateTimeField):
    def value_to_string(self, obj):
        val = self.value_from_object(obj)
        if val:
            val.replace(microsecond=0)
            return val.isoformat()
        return ''