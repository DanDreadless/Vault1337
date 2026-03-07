"""
STIX 2.1 export helpers.

Two public functions:
  - build_stix_bundle_for_file(file_instance)  → JSON string
  - build_stix_bundle_for_iocs(ioc_qs)         → JSON string

IOC type → STIX mapping:
  ip        → IPv4Address / IPv6Address SCO  + Indicator SDO
  domain    → DomainName SCO                 + Indicator SDO
  url       → URL SCO                        + Indicator SDO
  email     → EmailAddress SCO               + Indicator SDO
  registry  → WindowsRegistryKey SCO         + Indicator SDO
  cve       → Vulnerability SDO
  other     → Note SDO (value preserved as abstract text)
"""

import ipaddress
import logging
from datetime import datetime, timezone

import stix2

from vault.models import File, IOC

logger = logging.getLogger(__name__)

_PLATFORM_IDENTITY = stix2.Identity(
    name='Vault1337',
    identity_class='system',
    description='Vault1337 Malware Analysis Platform',
)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _escape(value: str) -> str:
    """Escape single quotes for STIX pattern strings."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _ioc_to_stix_objects(ioc: IOC) -> list:
    """
    Convert one IOC to a list of STIX objects (observable + indicator,
    or vulnerability, or note). Returns empty list on failure.
    """
    v = ioc.value
    indicator_types = ['malicious-activity'] if ioc.true_or_false else ['anomalous-activity']
    valid_from = _now()

    try:
        if ioc.type == 'ip':
            try:
                addr = ipaddress.ip_address(v)
                if addr.version == 6:
                    obs = stix2.IPv6Address(value=v)
                    pattern = f"[ipv6-addr:value = '{_escape(v)}']"
                else:
                    obs = stix2.IPv4Address(value=v)
                    pattern = f"[ipv4-addr:value = '{_escape(v)}']"
            except ValueError:
                obs = stix2.IPv4Address(value=v)
                pattern = f"[ipv4-addr:value = '{_escape(v)}']"
            ind = stix2.Indicator(
                name=f'IP: {v}',
                pattern=pattern,
                pattern_type='stix',
                valid_from=valid_from,
                indicator_types=indicator_types,
                created_by_ref=_PLATFORM_IDENTITY.id,
            )
            return [obs, ind]

        elif ioc.type == 'domain':
            obs = stix2.DomainName(value=v)
            ind = stix2.Indicator(
                name=f'Domain: {v}',
                pattern=f"[domain-name:value = '{_escape(v)}']",
                pattern_type='stix',
                valid_from=valid_from,
                indicator_types=indicator_types,
                created_by_ref=_PLATFORM_IDENTITY.id,
            )
            return [obs, ind]

        elif ioc.type == 'url':
            obs = stix2.URL(value=v)
            ind = stix2.Indicator(
                name=f'URL: {v}',
                pattern=f"[url:value = '{_escape(v)}']",
                pattern_type='stix',
                valid_from=valid_from,
                indicator_types=indicator_types,
                created_by_ref=_PLATFORM_IDENTITY.id,
            )
            return [obs, ind]

        elif ioc.type == 'email':
            obs = stix2.EmailAddress(value=v)
            ind = stix2.Indicator(
                name=f'Email: {v}',
                pattern=f"[email-addr:value = '{_escape(v)}']",
                pattern_type='stix',
                valid_from=valid_from,
                indicator_types=indicator_types,
                created_by_ref=_PLATFORM_IDENTITY.id,
            )
            return [obs, ind]

        elif ioc.type == 'registry':
            obs = stix2.WindowsRegistryKey(key=v)
            ind = stix2.Indicator(
                name=f'Registry: {v}',
                pattern=f"[windows-registry-key:key = '{_escape(v)}']",
                pattern_type='stix',
                valid_from=valid_from,
                indicator_types=indicator_types,
                created_by_ref=_PLATFORM_IDENTITY.id,
            )
            return [obs, ind]

        elif ioc.type == 'cve':
            vuln = stix2.Vulnerability(
                name=v,
                external_references=[
                    stix2.ExternalReference(
                        source_name='cve',
                        external_id=v,
                        url=f'https://nvd.nist.gov/vuln/detail/{v}',
                    )
                ],
                created_by_ref=_PLATFORM_IDENTITY.id,
            )
            return [vuln]

        else:
            # bitcoin, named_pipe, win_persistence, scheduled_task,
            # linux_cron, systemd_unit, macos_launchagent → Note
            note = stix2.Note(
                abstract=f'{ioc.type}: {v}',
                content=f'IOC type: {ioc.type}\nValue: {v}\nTrue positive: {ioc.true_or_false}',
                created_by_ref=_PLATFORM_IDENTITY.id,
                object_refs=[_PLATFORM_IDENTITY.id],
            )
            return [note]

    except Exception as exc:
        logger.warning('stix_export: failed to convert IOC %d (%s %s): %s', ioc.pk, ioc.type, v, exc)
        return []


def build_stix_bundle_for_file(file_instance: File) -> str:
    """
    Build a STIX 2.1 bundle for a File and all of its associated IOCs.
    Returns the bundle as a JSON string.
    """
    objects: list = [_PLATFORM_IDENTITY]

    # File SCO with hashes
    file_sco = stix2.File(
        name=file_instance.name or file_instance.sha256,
        size=file_instance.size,
        mime_type=file_instance.mime or None,
        hashes={
            'MD5': file_instance.md5,
            'SHA-1': file_instance.sha1,
            'SHA-256': file_instance.sha256,
            'SHA-512': file_instance.sha512,
        },
    )
    objects.append(file_sco)

    # Indicator for the file hash itself
    file_indicator = stix2.Indicator(
        name=f'File: {file_instance.name or file_instance.sha256}',
        pattern=f"[file:hashes.'SHA-256' = '{file_instance.sha256}']",
        pattern_type='stix',
        valid_from=_now(),
        indicator_types=['malicious-activity'],
        description=(
            f'MD5: {file_instance.md5}\n'
            f'SHA1: {file_instance.sha1}\n'
            f'SHA256: {file_instance.sha256}\n'
            f'MIME: {file_instance.mime}\n'
            f'Magic: {file_instance.magic}'
        ),
        created_by_ref=_PLATFORM_IDENTITY.id,
    )
    objects.append(file_indicator)

    # IOCs
    iocs = list(file_instance.iocs.all())
    for ioc in iocs:
        objects.extend(_ioc_to_stix_objects(ioc))

    bundle = stix2.Bundle(*objects)
    return bundle.serialize(pretty=True)


def build_stix_bundle_for_iocs(ioc_qs) -> str:
    """
    Build a STIX 2.1 bundle from a queryset / list of IOC objects.
    Returns the bundle as a JSON string.
    """
    objects: list = [_PLATFORM_IDENTITY]

    for ioc in ioc_qs:
        objects.extend(_ioc_to_stix_objects(ioc))

    if len(objects) == 1:
        # Only the identity — add a placeholder note
        objects.append(stix2.Note(
            abstract='Empty export',
            content='No exportable IOCs were found in the selection.',
            created_by_ref=_PLATFORM_IDENTITY.id,
            object_refs=[_PLATFORM_IDENTITY.id],
        ))

    bundle = stix2.Bundle(*objects)
    return bundle.serialize(pretty=True)
