"""Opt-in VirusTotal enrichment for the links found in a message.

Network access is isolated here so the analyzer stays offline. Note that a
lookup tells VirusTotal which URLs were in the message; it does not upload
the message itself. The free API tier is limited to about 4 requests per
minute, hence the delay between lookups.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from .analyzer import Finding, Report, rescore

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/"


def vt_url_id(url: str) -> str:
    """VirusTotal identifies a URL by its URL-safe base64, without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def vt_lookup(
    url: str,
    api_key: str,
    timeout: float = 10.0,
    opener: Callable = urllib.request.urlopen,
) -> Optional[dict]:
    """Verdict counts for a URL, {"status": "unknown"} if VT has never seen it,
    or None if the lookup failed. A GET never triggers a new scan."""
    request = urllib.request.Request(
        VT_URL_ENDPOINT + vt_url_id(url),
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as exc:  # must come before URLError (its parent)
        return {"status": "unknown"} if exc.code == 404 else None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
        return None
    return {
        "status": "known",
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
    }


def enrich_report(
    report: Report,
    api_key: str,
    max_lookups: int = 4,
    delay: float = 15.0,
    lookup: Callable[[str, str], Optional[dict]] = vt_lookup,
    sleep: Callable[[float], None] = time.sleep,
) -> Report:
    results: dict[str, Optional[dict]] = {}
    malicious: list[str] = []
    suspicious: list[str] = []

    for index, url in enumerate(report.urls[:max_lookups]):
        if index and delay:
            sleep(delay)
        result = lookup(url, api_key)
        results[url] = result
        if not result:
            continue
        if result.get("malicious"):
            malicious.append(f"{url} ({result['malicious']} engines)")
        elif result.get("suspicious"):
            suspicious.append(f"{url} ({result['suspicious']} engines)")

    if malicious:
        report.findings.append(
            Finding("vt_malicious", 40, "VirusTotal engines flag a link as malicious", malicious)
        )
    if suspicious:
        report.findings.append(
            Finding("vt_suspicious", 15, "VirusTotal engines flag a link as suspicious", suspicious)
        )
    report.enrichment = results
    return rescore(report)
