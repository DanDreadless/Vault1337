import hashlib
import os

def calculate_hashes(file):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()

    # Read the file in chunks to efficiently handle large files
    chunk_size = 8192  # You can adjust the chunk size based on your requirements

    # with file.open(mode='rb') as f:
    #     while chunk := f.read(chunk_size):
    #         magic = f.read(4).hex()

    with file.open(mode='rb') as f:
        while chunk := f.read(chunk_size):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
            sha512_hash.update(chunk)
            magic = f.read(4).hex()

    # Hexadecimal representations of the hash values
    md5 = md5_hash.hexdigest()
    # file deepcode ignore InsecureHash: <please specify a reason of ignoring this>
    sha1 = sha1_hash.hexdigest()
    sha256 = sha256_hash.hexdigest()
    sha512 = sha512_hash.hexdigest()
    mime = "test"
    magic = "test"
    size = 35 # os.stat(file).st_size

    return size, magic, mime, md5, sha1, sha256, sha512