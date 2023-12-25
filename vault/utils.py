import hashlib

def calculate_hashes(file):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    # Read the file in chunks to efficiently handle large files
    chunk_size = 8192  # You can adjust the chunk size based on your requirements

    with file.open(mode='rb') as f:
        while chunk := f.read(chunk_size):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    # Hexadecimal representations of the hash values
    md5 = md5_hash.hexdigest()
    sha1 = sha1_hash.hexdigest()
    sha256 = sha256_hash.hexdigest()

    return md5, sha1, sha256
