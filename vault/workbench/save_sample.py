import os
import zipfile
import py7zr
import hashlib
import logging

from ..models import File
from vault.utils import hash_sample
from vault.workbench.common import store_extracted_file
from vault.workbench.simhash import simhash_file
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
        fingerprint, bytes_hashed = simhash_file(fullpath)

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
            simhash=fingerprint,
            simhash_input_size=bytes_hashed,
        )
        vault_item.save()
        for tag in file_tags:
            vault_item.tag.add(tag.strip().lower())
        vault_item.save()

    def _safe_extract_path(self, storage_location: str, member_name: str):
        """
        Resolve the on-disk path that a member_name would extract to and verify
        it stays inside storage_location.  Returns the resolved path on success,
        or None if the member would escape the storage directory (Zip Slip).

        Defends against:
          - Absolute paths   : /etc/passwd
          - Path traversal   : ../../etc/cron.d/evil
          - Windows separators mixed in: ..\\..\\Windows\\System32\\evil
        """
        real_storage = os.path.realpath(storage_location)
        # Normalise separators and strip any leading slashes so os.path.join
        # cannot treat member_name as an absolute path.
        safe_name = member_name.replace('\\', '/').lstrip('/')
        candidate = os.path.realpath(os.path.join(real_storage, safe_name))
        if not candidate.startswith(real_storage + os.sep):
            return None
        return candidate

    def unzip_sample(self, storage_location):
        try:
            sha256 = None
            with zipfile.ZipFile(self.sample, 'r') as zip_ref:
                members = [m for m in zip_ref.infolist() if not m.filename.endswith('/')]

                # Validate every member path before extracting anything.
                # A single unsafe entry aborts the whole operation.
                for info in members:
                    if self._safe_extract_path(storage_location, info.filename) is None:
                        logger.warning(
                            "Zip Slip attempt blocked — unsafe member path: %s", info.filename
                        )
                        return "Error: Archive contains a path traversal entry — extraction aborted."

                # All members are safe; extract one at a time.
                pwd = self.password.encode() if self.password else None
                for info in members:
                    zip_ref.extract(info, path=storage_location, pwd=pwd)
                    extracted_path = os.path.join(storage_location, info.filename)
                    sha256, _, duplicate = store_extracted_file(
                        extracted_path, info.filename, self.tags,
                        self.uploaded_by, storage_location,
                    )
                    if duplicate:
                        return 'File already exists'

            return 'success', sha256
        except Exception as e:
            logger.exception(e)
            return str(e)

    def unzip_sample_7z(self, storage_location):
        # Use basename to prevent path injection via the upload filename.
        safe_upload_name = os.path.basename(self.sample.name)
        temp_file = os.path.join(storage_location, safe_upload_name)
        with open(temp_file, 'wb') as f:
            for chunk in self.sample.chunks():
                f.write(chunk)
        try:
            sha256 = None
            with py7zr.SevenZipFile(temp_file, mode='r', password=self.password) as archive:
                member_names = archive.getnames()

                # Validate every member path before extracting anything.
                for filename in member_names:
                    if self._safe_extract_path(storage_location, filename) is None:
                        logger.warning(
                            "Zip Slip attempt blocked — unsafe 7z member path: %s", filename
                        )
                        return "Error: Archive contains a path traversal entry — extraction aborted."

                # All members are safe; extract one at a time.
                for filename in member_names:
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
