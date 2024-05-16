# Other Imports
import os
import zipfile
import py7zr
import pyzipper
import hashlib
import mimetypes
# Django Imports
from ..models import File
from django.core.files.storage import FileSystemStorage

class SaveSample:
    def __init__(self, sample, tags, unzip, password):
        self.sample = sample
        self.tags = tags
        self.unzip = unzip
        self.password = password

    def save_file_and_update_model(self):
        storage_location =  './vault/samples/'
        # Get Sha256 to replace FileName
        sha256 = hashlib.sha256()
        for chunk in self.sample.chunks():
            sha256.update(chunk)
        sha256 =  sha256.hexdigest()
        fullpath = os.path.join(storage_location, sha256)
        if self.unzip=='on' and self.sample.name.endswith('.zip'):
            unzipper = SaveSample.unzip_sample(self, storage_location)
            if unzipper == 'success':
                return sha256
            else:
                return unzipper
        if self.unzip=='on' and self.sample.name.endswith('.7z'):
            unzipper = SaveSample.unzip_sample_7z(self, storage_location)
            if unzipper == 'success':
                return sha256
            else:
                return unzipper
        else:
            # Set the storage location
            fs = FileSystemStorage(location=storage_location)
            if File.objects.filter(sha256=sha256).exists():
                return 'File already exists'
            else:
                # Save the file to the storage location
                fs.save(sha256, self.sample)
            # Save the file to the model
            SaveSample.save_to_model(self, fullpath)
            return sha256
    
    def save_to_model(self, fullpath):
        # Calculate hash values using a utility function
        md5, sha1, sha256, sha512, magic_byte, size, mime = SaveSample.hash_sample(self, fullpath)
        # Create a new VaultItem instance and save it to the database
        vault_item = File(
            name=self.sample.name,
            size=size,
            magic=magic_byte,
            mime=self.sample.content_type,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            tag=self.tags,
        )
        vault_item.save()
        
    def hash_sample(self, fullpath):
        fullpath = fullpath
        size = os.stat(fullpath).st_size
        mime = mimetypes.guess_type(fullpath)[0]

        # Open the file in binary mode
        with open(fullpath, 'rb') as file:
            file_content = file.read()
            md5 = hashlib.md5(file_content).hexdigest()
            sha1 = hashlib.sha1(file_content).hexdigest()
            sha256 = hashlib.sha256(file_content).hexdigest()
            sha512 = hashlib.sha512(file_content).hexdigest()
            magic_byte = file_content[:4].hex()
        
        return md5, sha1, sha256, sha512, magic_byte, size, mime

    def unzip_sample(self, storage_location):
        try:
            with zipfile.ZipFile(self.sample, 'r') as zip_ref:
                if self.password:  # Check if a password is provided
                    zip_ref.extractall(storage_location, pwd=self.password.encode())
                else:
                    zip_ref.extractall(storage_location)
                
                # Loop through the extracted files
                for extracted_file in zip_ref.namelist():
                    extracted_file_path = os.path.join(storage_location, extracted_file)
                    # Calculate hash values using a utility function
                    md5, sha1, sha256, sha512, magic_byte, size, mime = SaveSample.hash_sample(self, extracted_file_path)
                    
                    # Check if the file already exists in the database
                    if File.objects.filter(sha256=sha256).exists():
                        os.remove(extracted_file_path)
                        return 'File already exists'
                    # Rename the extracted file to its SHA256 hash to ensure uniqueness
                    new_file_name = os.path.join(storage_location, sha256)
                    os.rename(extracted_file_path, new_file_name)
                    
                    # Save the file to the database with its original name and SHA256 hash
                    vault_item = File(
                        name=extracted_file,
                        size=size,
                        magic=magic_byte,
                        mime=mime,
                        md5=md5,
                        sha1=sha1,
                        sha256=sha256,
                        sha512=sha512,
                        tag=self.tags,
                    )
                    vault_item.save()

            return 'success'
        except Exception as e:
            return f"{str(e)}"

    def unzip_sample_7z(self, storage_location):
        try:
            with py7zr.SevenZipFile(self.sample, mode='r', password=self.password) as archive:
                for extracted_file in archive.getnames():
                    archive.extract(path=storage_location, targets=[extracted_file])
                    extracted_file_path = os.path.join(storage_location, extracted_file)
                    # Calculate hash values using a utility function
                    md5, sha1, sha256, sha512, magic_byte, size, mime = SaveSample.hash_sample(self, extracted_file_path)
                    
                    # Check if the file already exists in the database
                    if File.objects.filter(sha256=sha256).exists():
                        os.remove(extracted_file_path)
                        return 'File already exists'
                    # Rename the extracted file to its SHA256 hash to ensure uniqueness
                    new_file_name = os.path.join(storage_location, sha256)
                    os.rename(extracted_file_path, new_file_name)
                    
                    # Save the file to the database with its original name and SHA256 hash
                    vault_item = File(
                        name=extracted_file,
                        size=size,
                        magic=magic_byte,
                        mime=mime,
                        md5=md5,
                        sha1=sha1,
                        sha256=sha256,
                        sha512=sha512,
                        tag=self.tags,
                    )
                    vault_item.save()
                    return 'success'
        except Exception as e:
            return f"{str(e)}"

