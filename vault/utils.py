import os
import hashlib
from django.db import models


def add_file(file):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()
    magic_byte = file.read(2).hex()
    size = file.size

    # Read the file in chunks to efficiently handle large files
    chunk_size = 8192  # You can adjust the chunk size based on your requirements

    for chunk in file.chunks():
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)
        sha512_hash.update(chunk)

    # Hexadecimal representations of the hash values
    md5 = md5_hash.hexdigest()  # file deepcode ignore InsecureHash: Temp ignoring to focus on getting the base code put together
    sha1 = sha1_hash.hexdigest()
    sha256 = sha256_hash.hexdigest()
    sha512 = sha512_hash.hexdigest()
    return md5, sha1, sha256, sha512, magic_byte, size

def url_hashing(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()
    size = os.stat(file_path).st_size

    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        # Read and update hash string value in blocks of 4K
        magic_byte = file.read(4).hex()

        for byte_block in iter(lambda: file.read(4096), b""):
            md5_hash.update(byte_block)
            sha1_hash.update(byte_block)
            sha256_hash.update(byte_block)
            sha512_hash.update(byte_block)

    md5 = md5_hash.hexdigest()  # file deepcode ignore InsecureHash: Temp ignoring to focus on getting the base code put together
    sha1 = sha1_hash.hexdigest()
    sha256 = sha256_hash.hexdigest()
    sha512 = sha512_hash.hexdigest()
    size = size

    return md5, sha1, sha256, sha512, magic_byte, size

class CustomDateTimeField(models.DateTimeField):
    def value_to_string(self, obj):
        val = self.value_from_object(obj)
        if val:
            val.replace(microsecond=0)
            return val.isoformat()
        return ''