# Other Imports
import os
import zipfile
import py7zr
import hashlib
import mimetypes
# Django Imports
from ..models import File
from django.core.files.storage import FileSystemStorage
from django.conf import settings

class ExtractZip:
    def __init__(self, file_location, tags, unzip, password, uploaded_by):
        self.file_location = file_location
        self.tags = tags.split(',') if tags else []  # Split tags into a list
        self.unzip = unzip
        self.password = password
        self.uploaded_by = uploaded_by

    def extract_file_and_update_model(self):
        storage_location = settings.SAMPLE_STORAGE_DIR
        sha256 = self.file_location.split('/')[-1]
        instance = File.objects.filter(sha256=sha256)
        if instance.exists():
            file_name = instance.first().name
        else:
            return 'File does not exist'
        if self.unzip=='on' and file_name.endswith('.zip'):
            unzipper = ExtractZip.unzip_sample(self, storage_location)
            return unzipper
        if self.unzip=='on' and file_name.endswith('.7z'):
            unzipper = ExtractZip.unzip_sample_7z(self, storage_location)
            return unzipper
        
    def hash_sample(self, fullpath):
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
    
    def unzip_sample(self, storage_location):
        try:
            with zipfile.ZipFile(self.file_location, 'r') as zip_ref:
                if self.password:  # Check if a password is provided
                    zip_ref.extractall(storage_location, pwd=self.password.encode())
                else:
                    zip_ref.extractall(storage_location)
                
                # Loop through the extracted files
                for extracted_file in zip_ref.namelist():
                    extracted_file_path = os.path.join(storage_location, extracted_file)
                    # Calculate hash values using a utility function
                    md5, sha1, sha256, sha512, magic_byte, size, mime = ExtractZip.hash_sample(self, extracted_file_path)
                    
                    # Check if the file already exists in the database
                    if File.objects.filter(sha256=sha256).exists():
                        os.remove(extracted_file_path)
                        return 'File already exists'
                    # Rename the extracted file to its SHA256 hash to ensure uniqueness
                    new_file_name = os.path.join(storage_location, sha256)
                    os.rename(extracted_file_path, new_file_name)
                    
                    # Add the file extension as a tag
                    try:
                        ext_check = extracted_file.split('.')
                        if len(ext_check) > 1:
                            filetype = extracted_file.split('.')[-1]
                            self.tags.append(filetype)
                    except:
                        filetype = ''

                    if mime is None:
                        mime = 'Unknown'
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
                        uploaded_by=self.uploaded_by,                        
                    )
                    vault_item.save()

                    # Add tags to the model
                    for tag in self.tags:
                        vault_item.tag.add(tag.strip())
                    vault_item.save()
                    
            return 'success', sha256

        except Exception as e:
            return f"{str(e)}"

    def unzip_sample_7z(self, storage_location):
        try:
            with py7zr.SevenZipFile(self.file_location, mode='r', password=self.password) as archive:
                for extracted_file in archive.getnames():
                    archive.extract(path=storage_location, targets=[extracted_file])
                    extracted_file_path = os.path.join(storage_location, extracted_file)
                    # Calculate hash values using a utility function
                    md5, sha1, sha256, sha512, magic_byte, size, mime = ExtractZip.hash_sample(self, extracted_file_path)
                    
                    # Check if the file already exists in the database
                    if File.objects.filter(sha256=sha256).exists():
                        os.remove(extracted_file_path)
                        return 'File already exists'
                    # Rename the extracted file to its SHA256 hash to ensure uniqueness
                    new_file_name = os.path.join(storage_location, sha256)
                    os.rename(extracted_file_path, new_file_name)
                    
                    # Add the file extension as a tag
                    try:
                        ext_check = extracted_file.split('.')
                        if len(ext_check) > 1:
                            filetype = extracted_file.split('.')[-1]
                            self.tags.append(filetype)
                    except:
                        filetype = ''
                    if mime is None:
                        mime = 'Unknown'
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
                        uploaded_by=self.uploaded_by,
                    )
                    vault_item.save()

                    # Add tags to the model
                    for tag in self.tags:
                        vault_item.tag.add(tag.strip())
                    vault_item.save()

            return 'success', sha256
                
        except Exception as e:
            return f"{str(e)}"