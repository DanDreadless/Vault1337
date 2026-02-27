import os
import tempfile
import zipfile
import py7zr
import logging

from ..models import File
from vault.workbench.common import store_extracted_file
from django.conf import settings

logger = logging.getLogger(__name__)

# Archive magic bytes
_MAGIC_ZIP = b'PK\x03\x04'
_MAGIC_7Z  = b'7z\xbc\xaf\x27\x1c'


# ---------------------------------------------------------------------------
# Tools-tab entry point
# ---------------------------------------------------------------------------

def extract_archive(file_path, password, user):
    """
    Detect archive type from magic bytes, extract all contained files into the
    vault, and return a structured result dict::

        {
            'text':  str,                      # formatted summary for <pre> display
            'files': [                         # one entry per contained file
                {'sha256': str, 'id': int, 'name': str, 'duplicate': bool},
                ...
            ]
        }
    """
    storage_location = settings.SAMPLE_STORAGE_DIR

    try:
        with open(file_path, 'rb') as f:
            magic = f.read(6)
    except Exception as e:
        return {'text': f'Error reading file: {e}', 'files': []}

    if magic[:4] == _MAGIC_ZIP:
        return _extract_zip(file_path, password, user, storage_location)
    elif magic[:6] == _MAGIC_7Z:
        return _extract_7z(file_path, password, user, storage_location)
    else:
        return {
            'text': f'Unsupported archive type (magic bytes: {magic[:4].hex()}). Supported formats: ZIP, 7z.',
            'files': [],
        }


def _extract_zip(file_path, password, user, storage_location):
    files, errors = [], []
    pwd = password.encode() if password else None
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    data = zf.read(info.filename, pwd=pwd)
                    sha256, file_id, duplicate = _store_bytes(
                        data, info.filename, user, storage_location
                    )
                    files.append({
                        'sha256': sha256, 'id': file_id,
                        'name': info.filename, 'duplicate': duplicate,
                    })
                except Exception as e:
                    logger.exception(e)
                    errors.append(f'{info.filename}: {e}')
    except Exception as e:
        logger.exception(e)
        return {'text': f'Error opening ZIP: {e}', 'files': []}
    return _format_result(files, errors)


def _extract_7z(file_path, password, user, storage_location):
    files, errors = [], []
    try:
        with py7zr.SevenZipFile(file_path, mode='r', password=password) as archive:
            all_files = {name for name in archive.getnames() if not name.endswith('/')}
            file_data = archive.read(targets=list(all_files))
            for filename, bio in file_data.items():
                try:
                    sha256, file_id, duplicate = _store_bytes(
                        bio.read(), filename, user, storage_location
                    )
                    files.append({
                        'sha256': sha256, 'id': file_id,
                        'name': filename, 'duplicate': duplicate,
                    })
                except Exception as e:
                    logger.exception(e)
                    errors.append(f'{filename}: {e}')
    except Exception as e:
        logger.exception(e)
        return {'text': f'Error opening 7z: {e}', 'files': []}
    return _format_result(files, errors)


def _store_bytes(data, filename, user, storage_location):
    """Write bytes to a temp file then hand off to store_extracted_file."""
    fd, tmp_path = tempfile.mkstemp(dir=storage_location)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        return store_extracted_file(tmp_path, filename, ['zip_extracted'], user, storage_location)
    except Exception:
        # Clean up temp file if store_extracted_file raised before renaming it
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _format_result(files, errors):
    new   = [f for f in files if not f['duplicate']]
    dupes = [f for f in files if f['duplicate']]
    lines = []
    if new:
        lines.append(f'Extracted {len(new)} new file(s):')
        for f in new:
            lines.append(f"  {f['sha256']}  {f['name']}")
    if dupes:
        lines.append(f'\n{len(dupes)} file(s) already in vault:')
        for f in dupes:
            lines.append(f"  {f['sha256']}  {f['name']}")
    if errors:
        lines.append(f'\n{len(errors)} error(s):')
        for e in errors:
            lines.append(f'  {e}')
    if not lines:
        lines.append('No files extracted.')
    return {'text': '\n'.join(lines), 'files': files}


# ---------------------------------------------------------------------------
# Upload-flow class (used by SaveSample / API upload endpoint)
# ---------------------------------------------------------------------------

class ExtractZip:
    """Extract an already-stored archive file on disk into the vault."""

    def __init__(self, file_location, tags, unzip, password, uploaded_by):
        self.file_location = file_location
        self.tags = tags.split(',') if tags else []
        self.unzip = unzip
        self.password = password
        self.uploaded_by = uploaded_by

    def extract_file_and_update_model(self):
        storage_location = settings.SAMPLE_STORAGE_DIR
        sha256 = os.path.basename(self.file_location)
        instance = File.objects.filter(sha256=sha256).first()
        if not instance:
            return 'File does not exist'

        if self.unzip == 'on' and instance.name.endswith('.zip'):
            return self._unzip_sample(storage_location)
        if self.unzip == 'on' and instance.name.endswith('.7z'):
            return self._unzip_sample_7z(storage_location)

    def _unzip_sample(self, storage_location):
        try:
            sha256 = None
            with zipfile.ZipFile(self.file_location, 'r') as zf:
                pwd = self.password.encode() if self.password else None
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    data = zf.read(info.filename, pwd=pwd)
                    sha256, _, duplicate = _store_bytes(
                        data, info.filename, self.uploaded_by, storage_location
                    )
                    if duplicate:
                        return 'File already exists'
            return 'success', sha256
        except Exception as e:
            logger.exception(e)
            return str(e)

    def _unzip_sample_7z(self, storage_location):
        try:
            sha256 = None
            with py7zr.SevenZipFile(self.file_location, mode='r', password=self.password) as archive:
                all_files = {name for name in archive.getnames() if not name.endswith('/')}
                file_data = archive.read(targets=list(all_files))
                for filename, bio in file_data.items():
                    sha256, _, duplicate = _store_bytes(
                        bio.read(), filename, self.uploaded_by, storage_location
                    )
                    if duplicate:
                        return 'File already exists'
            return 'success', sha256
        except Exception as e:
            logger.exception(e)
            return str(e)
