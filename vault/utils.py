import hashlib
import os


def add_file(file):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()

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

    return md5, sha1, sha256, sha512

# def get_magic_bytes(file):
#     with file.open(mode='rb') as f:
#         magic = f.read(4).hex()
#     return magic

# def get_file_size(file):
#     size = os.stat(file).st_size
#     return size