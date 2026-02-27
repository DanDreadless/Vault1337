import os
import logging

logger = logging.getLogger(__name__)


def store_extracted_file(extracted_file_path, filename, tags, uploaded_by, storage_location):
    # Lazy imports to avoid circular dependency (vault.utils imports vault.workbench at module level)
    from vault.models import File
    from vault.utils import hash_sample
    """
    Hash a freshly extracted file, check for duplicates, rename it to its SHA256,
    create a File model entry, and apply tags.

    Returns (sha256, duplicate) where duplicate=True means the file already existed
    in the vault and has been removed from disk.
    """
    md5, sha1, sha256, sha512, magic_byte, size, mime = hash_sample(extracted_file_path)

    existing = File.objects.filter(sha256=sha256).first()
    if existing:
        os.remove(extracted_file_path)
        return sha256, existing.id, True

    new_path = os.path.join(storage_location, sha256)
    os.rename(extracted_file_path, new_path)

    file_tags = list(tags)
    try:
        parts = filename.split('.')
        if len(parts) > 1:
            file_tags.append(parts[-1])
    except Exception as e:
        logger.exception(e)

    if mime is None:
        mime = 'Unknown'

    vault_item = File(
        name=filename,
        size=size,
        magic=magic_byte,
        mime=mime,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        sha512=sha512,
        uploaded_by=uploaded_by,
    )
    vault_item.save()

    for tag in file_tags:
        vault_item.tag.add(tag.strip().lower())
    vault_item.save()

    # Auto-enrich with VirusTotal (mirrors the behaviour in api/views.py upload flows)
    try:
        from vault.utils import fetch_vt_report
        vt_result = fetch_vt_report(sha256)
        if vt_result is not None:
            vault_item.vt_data = vt_result
            vault_item.save(update_fields=['vt_data'])
            threat_label = (vt_result.get('popular_threat_classification') or {}).get('suggested_threat_label', '')
            if threat_label:
                vault_item.tag.add(threat_label.lower())
    except Exception as e:
        logger.warning("VT enrichment failed for %s: %s", sha256, e)

    return sha256, vault_item.id, False
