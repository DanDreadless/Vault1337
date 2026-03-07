"""
IOC Enrichment module.

Provides two public entry points:

  enrich_ioc(ioc)
      Enriches a single IOC synchronously, calling VT and AbuseIPDB
      concurrently via ThreadPoolExecutor.  Used by the per-IOC API action.
      Always clears manually_overridden before enriching (explicit re-enrich
      means the analyst wants fresh threat-intel regardless of prior overrides).

  enrich_iocs_batch(iocs)
      Designed to be spawned in a daemon thread by extract_and_save_iocs so
      the tool response returns immediately.  Groups IOCs by type and processes
      all IPs then all domains sequentially, sleeping between VT calls to
      respect the free-tier rate limit.  Respects manually_overridden — IOCs
      that an analyst has manually classified are not touched.

Enriched types: ip (VT + AbuseIPDB), domain (VT only).
URL enrichment is deferred — VT URL IDs require base64url encoding.

All external API calls are gated by isinstance(result, dict) since the
existing utils functions return strings on error/missing key rather than
raising exceptions.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List

from django.conf import settings
from django.db import close_old_connections

from vault.models import IOC
from vault.utils import get_abuseipdb_data, get_otx_data, get_vt_data, get_vt_domain_data

logger = logging.getLogger(__name__)

# ---- Threshold / delay settings (configurable via Django settings / .env) ----

def _vt_threshold() -> int:
    return getattr(settings, 'IOC_VT_MALICIOUS_THRESHOLD', 1)

def _abuse_threshold() -> int:
    return getattr(settings, 'IOC_ABUSEIPDB_SCORE_THRESHOLD', 25)

def _otx_threshold() -> int:
    return getattr(settings, 'IOC_OTX_PULSE_THRESHOLD', 1)

def _vt_delay() -> int:
    return getattr(settings, 'IOC_ENRICH_VT_DELAY_SECONDS', 15)


# ---- Internal per-type enrichment helpers ----

def _enrich_ip(ioc: IOC) -> None:
    """
    Enrich an IP IOC by calling VT, AbuseIPDB, and OTX concurrently.
    Updates ioc.enriched, ioc.enriched_at, and ioc.true_or_false in-place
    then saves.  Does not touch manually_overridden.
    """
    enriched: dict = {}
    is_malicious = False
    all_failed = True

    def _call_vt():
        return ('vt', get_vt_data(ioc.value))

    def _call_abuse():
        return ('abuseipdb', get_abuseipdb_data(ioc.value))

    def _call_otx():
        return ('otx', get_otx_data(ioc.value, 'ip'))

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(_call_vt), pool.submit(_call_abuse), pool.submit(_call_otx)]
        for future in as_completed(futures):
            try:
                source, result = future.result()
            except Exception as exc:
                logger.warning("IOC enrichment thread error for %s: %s", ioc.value, exc)
                continue

            if not isinstance(result, dict):
                logger.debug("IOC enrichment skipped for %s (%s): %s", ioc.value, source, result)
                continue

            all_failed = False

            if source == 'vt':
                attrs = result.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values()) if stats else 0
                enriched['vt'] = {'malicious': malicious, 'total': total}
                if malicious >= _vt_threshold():
                    is_malicious = True

            elif source == 'abuseipdb':
                data = result.get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                enriched['abuseipdb'] = {'score': score}
                if score >= _abuse_threshold():
                    is_malicious = True

            elif source == 'otx':
                pulse_count = result.get('pulse_count', 0)
                enriched['otx'] = {'pulse_count': pulse_count}
                if pulse_count >= _otx_threshold():
                    is_malicious = True

    if all_failed:
        logger.debug("All enrichment sources failed for IP %s; leaving verdict unchanged.", ioc.value)
        return

    ioc.enriched = enriched
    ioc.enriched_at = datetime.now(tz=timezone.utc)
    ioc.true_or_false = is_malicious
    ioc.save(update_fields=['enriched', 'enriched_at', 'true_or_false'])


def _enrich_domain(ioc: IOC) -> None:
    """
    Enrich a domain IOC via VirusTotal and OTX concurrently.
    Updates ioc.enriched, ioc.enriched_at, and ioc.true_or_false in-place
    then saves.  Does not touch manually_overridden.
    """
    enriched: dict = {}
    is_malicious = False
    all_failed = True

    def _call_vt():
        return ('vt', get_vt_domain_data(ioc.value))

    def _call_otx():
        return ('otx', get_otx_data(ioc.value, 'domain'))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_call_vt), pool.submit(_call_otx)]
        for future in as_completed(futures):
            try:
                source, result = future.result()
            except Exception as exc:
                logger.warning("IOC enrichment thread error for %s: %s", ioc.value, exc)
                continue

            if not isinstance(result, dict):
                logger.debug("IOC enrichment skipped for %s (%s): %s", ioc.value, source, result)
                continue

            all_failed = False

            if source == 'vt':
                attrs = result.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values()) if stats else 0
                enriched['vt'] = {'malicious': malicious, 'total': total}
                if malicious >= _vt_threshold():
                    is_malicious = True

            elif source == 'otx':
                pulse_count = result.get('pulse_count', 0)
                enriched['otx'] = {'pulse_count': pulse_count}
                if pulse_count >= _otx_threshold():
                    is_malicious = True

    if all_failed:
        logger.debug("All enrichment sources failed for domain %s; leaving verdict unchanged.", ioc.value)
        return

    ioc.enriched = enriched
    ioc.enriched_at = datetime.now(tz=timezone.utc)
    ioc.true_or_false = is_malicious
    ioc.save(update_fields=['enriched', 'enriched_at', 'true_or_false'])


# ---- Public API ----

def enrich_ioc(ioc: IOC) -> None:
    """
    Enrich a single IOC synchronously.  Intended for the per-IOC API action.

    Always clears manually_overridden first — an explicit re-enrich request
    means the analyst wants fresh threat-intel regardless of prior overrides.
    Unsupported IOC types are silently ignored.
    """
    if ioc.type not in ('ip', 'domain'):
        return

    # Clear the manual override so the enrichment result takes effect.
    if ioc.manually_overridden:
        ioc.manually_overridden = False
        ioc.save(update_fields=['manually_overridden'])

    try:
        if ioc.type == 'ip':
            _enrich_ip(ioc)
        elif ioc.type == 'domain':
            _enrich_domain(ioc)
    except Exception:
        logger.exception("Unexpected error enriching IOC %s (%s)", ioc.value, ioc.type)


def enrich_iocs_batch(iocs: List[IOC]) -> None:
    """
    Enrich a list of IOCs in batch.  Intended to run in a daemon thread
    spawned by extract_and_save_iocs — do not call from a request handler
    directly as it sleeps between VT calls.

    Processes all IPs first, then all domains.  Skips any IOC where
    manually_overridden is True (analyst classification takes precedence).
    Sleeps IOC_ENRICH_VT_DELAY_SECONDS between each VT call to stay within
    the free-tier 4-requests-per-minute limit.
    """
    # Ensure this daemon thread uses a fresh DB connection.  Django does not
    # automatically clean up connections opened in background threads, which
    # causes connection leaks against PostgreSQL in multi-worker production.
    close_old_connections()
    try:
        ips = [i for i in iocs if i.type == 'ip' and not i.manually_overridden]
        domains = [i for i in iocs if i.type == 'domain' and not i.manually_overridden]
        delay = _vt_delay()

        for idx, ioc in enumerate(ips):
            try:
                _enrich_ip(ioc)
                logger.debug("Enriched IP IOC: %s", ioc.value)
            except Exception:
                logger.exception("Batch enrichment error for IP %s", ioc.value)
            # Sleep between VT calls but not after the last one before domains
            # (domains will sleep before their own first call below).
            if idx < len(ips) - 1 or domains:
                time.sleep(delay)

        for idx, ioc in enumerate(domains):
            try:
                _enrich_domain(ioc)
                logger.debug("Enriched domain IOC: %s", ioc.value)
            except Exception:
                logger.exception("Batch enrichment error for domain %s", ioc.value)
            if idx < len(domains) - 1:
                time.sleep(delay)
    finally:
        close_old_connections()
