import os
import zipfile
import py7zr
import hashlib
import logging

from ..models import File
from vault.utils import hash_sample
from vault.workbench.common import store_extracted_file
from django.core.files.storage import FileSystemStorage
from django.conf import settings

logger = logging.getLogger(__name__)


class SaveSample:
    def __init__(self, sample, tags, unzip, password, uploaded_by):
        self.sample = sample
        self.tags = tags.split(',') if tags else []
        self.unzip = unzip
        self.password = password
        self.uploaded_by = uploaded_by

    def save_file_and_update_model(self):
        storage_location = settings.SAMPLE_STORAGE_DIR
        if self.unzip == 'on' and self.sample.name.endswith('.zip'):
            return self.unzip_sample(storage_location)
        if self.unzip == 'on' and self.sample.name.endswith('.7z'):
            return self.unzip_sample_7z(storage_location)

        sha256 = hashlib.sha256()
        for chunk in self.sample.chunks():
            sha256.update(chunk)
        sha256 = sha256.hexdigest()
        fullpath = os.path.join(storage_location, sha256)

        fs = FileSystemStorage(location=storage_location)
        if File.objects.filter(sha256=sha256).exists():
            return 'File already exists'
        fs.save(sha256, self.sample)
        self._save_to_model(fullpath)
        return 'success', sha256

    def _save_to_model(self, fullpath):
        md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(fullpath)

        file_tags = list(self.tags)
        try:
            parts = self.sample.name.split('.')
            if len(parts) > 1:
                file_tags.append(parts[-1])
        except Exception as e:
            logger.exception(e)

        vault_item = File(
            name=self.sample.name,
            size=size,
            magic=magic_byte,
            mime=self.sample.content_type,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            uploaded_by=self.uploaded_by,
        )
        vault_item.save()
        for tag in file_tags:
            vault_item.tag.add(tag.strip().lower())
        vault_item.save()

    def unzip_sample(self, storage_location):
        try:
            sha256 = None
            with zipfile.ZipFile(self.sample, 'r') as zip_ref:
                if self.password:
                    zip_ref.extractall(storage_location, pwd=self.password.encode())
                else:
                    zip_ref.extractall(storage_location)

                for filename in zip_ref.namelist():
                    extracted_path = os.path.join(storage_location, filename)
                    sha256, _, duplicate = store_extracted_file(
                        extracted_path, filename, self.tags,
                        self.uploaded_by, storage_location,
                    )
                    if duplicate:
                        return 'File already exists'

            return 'success', sha256
        except Exception as e:
            logger.exception(e)
            return str(e)

    def unzip_sample_7z(self, storage_location):
        temp_file = os.path.join(storage_location, self.sample.name)
        with open(temp_file, 'wb') as f:
            for chunk in self.sample.chunks():
                f.write(chunk)
        try:
            sha256 = None
            with py7zr.SevenZipFile(temp_file, mode='r', password=self.password) as archive:
                for filename in archive.getnames():
                    archive.extract(path=storage_location, targets=[filename])
                    extracted_path = os.path.join(storage_location, filename)
                    sha256, _, duplicate = store_extracted_file(
                        extracted_path, filename, self.tags,
                        self.uploaded_by, storage_location,
                    )
                    if duplicate:
                        return 'File already exists'

            os.remove(temp_file)
            return 'success', sha256
        except Exception as e:
            logger.exception(e)
            return str(e)
