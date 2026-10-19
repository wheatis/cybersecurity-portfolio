"""Heuristic phishing analysis of a single .eml message.

Everything in this module is offline and deterministic: no network access,
and no message content leaves the machine. Network enrichment lives in
enrich.py and is opt-in.

The score is additive and explainable: every finding carries the points it
adds, a human-readable message and the evidence that triggered it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlsplit

SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
     "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at"}
)
SUSPICIOUS_TLDS = frozenset({"zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq"})

# No public-suffix list on purpose (stdlib only): these second-level labels
# cover the common "co.uk"-style suffixes.
_SECOND_LEVEL = frozenset({"co", "com", "org", "net", "gov", "ac", "edu"})

URGENT_PHRASES = (
    # English
    "urgent", "immediately", "verify your account", "your account has been suspended",
    "account suspended", "confirm your identity", "password expires", "unusual activity",
    "click here", "final notice", "within 24 hours", "act now", "update your payment",
    # French
    "immédiatement", "vérifiez votre compte", "votre compte a été suspendu",
    "compte suspendu", "confirmez votre identité", "mot de passe expire",
    "activité inhabituelle", "cliquez ici", "dernier avertissement", "sous 24 heures",
    "mettre à jour votre paiement",
)

HIGH_RISK_EXT = frozenset(
    {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".bat", ".cmd", ".ps1",
     ".lnk", ".iso", ".img", ".msi", ".jar", ".hta", ".dll"}
)
MEDIUM_RISK_EXT = frozenset({".docm", ".xlsm", ".pptm", ".html", ".htm", ".one"})
LOW_RISK_EXT = frozenset({".zip", ".rar", ".7z", ".gz"})
_DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|lnk|com|ps1)$", re.I
)

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
_DOMAINISH_RE = re.compile(
    r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)|\b((?:[\w-]+\.)+[a-z]{2,})\b", re.I
)
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
]
MAX_EVIDENCE = 5


@dataclass
class Finding:
    rule: str
    points: int
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Link:
    href: str
    text: str = ""  # visible text of an HTML anchor


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class Report:
    subject: str
    sender: str
    origin_ip: Optional[str]
    urls: list[str]
    attachments: list[Attachment]
    findings: list[Finding]
    score: int = 0
    verdict: str = "low risk"
    enrichment: dict = field(default_factory=dict)


class _Collector:
    """One finding per rule: repeated hits only add evidence, not points."""

    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}

    def add(self, rule: str, points: int, message: str, evidence: str = "") -> None:
        finding = self.findings.get(rule)
        if finding is None:
            finding = self.findings[rule] = Finding(rule, points, message)
        if evidence and evidence not in finding.evidence and len(finding.evidence) < MAX_EVIDENCE:
            finding.evidence.append(evidence)


class _HtmlParser(HTMLParser):
    """Collects visible text and anchors (href + visible text)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[Link] = []
        self.text: list[str] = []
        self._href: Optional[str] = None
        self._anchor_text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = (dict(attrs).get("href") or "").strip() or None
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.anchors.append(Link(self._href, " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


# --------------------------------------------------------------------------- helpers


def base_domain(host: str) -> str:
    """Approximate registrable domain (no public-suffix list)."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _addr_domain(addr: str) -> str:
    return addr.rpartition("@")[2].strip("<> ").lower()


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip_like(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Decimal or hex encoded IPs, e.g. http://3232235777/ or http://0xC0A80001/
    return host.isdigit() or bool(re.fullmatch(r"0x[0-9a-f]+", host))


def _text_domain(text: str) -> str:
    """Domain a link's visible text pretends to point to, or ''."""
    text = text.strip()
    if re.match(r"https?://", text, re.I):
        return _host(text)
    match = re.fullmatch(r"(?:www\.)?((?:[\w-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?", text, re.I)
    return match.group(1).lower() if match else ""


def parse_auth_results(msg: EmailMessage) -> dict[str, str]:
    """SPF/DKIM/DMARC verdicts from Authentication-Results (topmost header wins).

    Only meaningful if the header was added by *your own* receiving server:
    a sender can forge this header, and it is not verified here.
    """
    results: dict[str, str] = {}
    for header in msg.get_all("Authentication-Results", []):
        for mechanism, verdict in _AUTH_RE.findall(str(header)):
            results.setdefault(mechanism.lower(), verdict.lower())
    return results


def origin_ip(msg: EmailMessage) -> Optional[str]:
    """Earliest non-private IPv4 found in the Received chain (best effort)."""
    for header in reversed(msg.get_all("Received", [])):  # last header = earliest hop
        for candidate in _IPV4_RE.findall(str(header)):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(ip in net for net in _PRIVATE_NETS):
                return str(ip)
    return None


# ------------------------------------------------------------------------ extraction


@dataclass
class _Content:
    plain: str = ""
    html_text: str = ""
    anchors: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


def _decode_part(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract(msg: EmailMessage) -> _Content:
    content = _Content()
    plain_parts: list[str] = []
    html_texts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        is_attachment = part.get_content_disposition() == "attachment" or (
            bool(filename) and not ctype.startswith("text/")
        )
        if is_attachment:
            data = part.get_payload(decode=True) or b""
            content.attachments.append(
                Attachment(filename or "(unnamed)", ctype, len(data), hashlib.sha256(data).hexdigest())
            )
        elif ctype == "text/plain":
            plain_parts.append(_decode_part(part))
        elif ctype == "text/html":
            parser = _HtmlParser()
            parser.feed(_decode_part(part))
            parser.close()
            content.anchors.extend(parser.anchors)
            html_texts.append(" ".join("".join(parser.text).split()))
    content.plain = "\n".join(plain_parts)
    content.html_text = "\n".join(html_texts)
    return content


def _collect_urls(content: _Content) -> list[str]:
    urls: dict[str, None] = {}
    for link in content.anchors:
        if re.match(r"https?://", link.href, re.I):
            urls.setdefault(link.href)
    for match in _URL_RE.findall(content.plain):
        urls.setdefault(match.rstrip(".,;:!?"))
    return list(urls)


# ---------------------------------------------------------------------------- checks


def _check_headers(msg: EmailMessage, f: _Collector) -> None:
    auth = parse_auth_results(msg)
    if not auth:
        f.add("auth_missing", 0,
              "No Authentication-Results header: SPF/DKIM/DMARC could not be assessed")
    else:
        spf, dkim, dmarc = auth.get("spf"), auth.get("dkim"), auth.get("dmarc")
        if spf == "fail":
            f.add("spf_fail", 20, "SPF failed: the sending server is not authorised for this domain")
        elif spf == "softfail":
            f.add("spf_softfail", 10, "SPF soft-failed: sending server is probably not authorised")
        if dkim == "fail":
            f.add("dkim_fail", 15, "DKIM signature failed verification")
        if dmarc == "fail":
            f.add("dmarc_fail", 25, "DMARC failed: the message does not align with the From domain policy")

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = _addr_domain(from_addr)
    if not from_domain:
        return
    from_base = base_domain(from_domain)

    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    if reply_to and base_domain(_addr_domain(reply_to)) != from_base:
        f.add("reply_to_mismatch", 15, "Reply-To domain differs from the From domain",
              f"From {from_domain} / Reply-To {_addr_domain(reply_to)}")

    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    if return_path and base_domain(_addr_domain(return_path)) != from_base:
        f.add("return_path_mismatch", 5,
              "Return-Path domain differs from the From domain (common for legitimate bulk senders too)",
              f"From {from_domain} / Return-Path {_addr_domain(return_path)}")

    for match in _DOMAINISH_RE.finditer(from_name):
        shown = (match.group(1) or match.group(2)).lower()
        if base_domain(shown) != from_base:
            f.add("display_name_spoof", 20,
                  "Display name shows a different domain than the real sender address",
                  f'"{from_name}" <{from_addr}>')


def _check_url(url: str, f: _Collector) -> None:
    try:
        parts = urlsplit(url)
    except ValueError:
        f.add("url_malformed", 5, "Malformed URL", url)
        return
    host = (parts.hostname or "").lower()
    if not host:
        return
    labels = host.split(".")
    ip_like = _is_ip_like(host)

    if ip_like:
        f.add("url_ip_host", 20, "Link points to a raw IP address instead of a domain", url)
    if "@" in parts.netloc:
        f.add("url_userinfo", 20, "Link uses 'user@host' syntax, often used to disguise the real host", url)
    if any(label.startswith("xn--") for label in labels):
        f.add("url_punycode", 15, "Link uses a punycode (internationalised) domain: possible lookalike", url)
    if parts.scheme.lower() == "http":
        f.add("url_http", 5, "Link uses unencrypted HTTP", url)
    if ip_like:
        return

    base = base_domain(host)
    if base in SHORTENERS:
        f.add("url_shortener", 10, "Link uses a URL shortener that hides the destination", url)
    if len(labels) - len(base.split(".")) >= 3:
        f.add("url_deep_subdomain", 10, "Link has a long subdomain chain, often used to bury the real domain", url)
    if labels[-1] in SUSPICIOUS_TLDS:
        f.add("url_suspicious_tld", 5, "Link uses a TLD frequently seen in abuse", url)


def _check_link_text(anchors: list[Link], f: _Collector) -> None:
    for link in anchors:
        shown = _text_domain(link.text)
        target = _host(link.href)
        if shown and target and base_domain(shown) != base_domain(target):
            f.add("link_text_mismatch", 30,
                  "A link displays one domain but points to another",
                  f"shows '{link.text}' -> goes to {link.href}")


def _check_language(subject: str, content: _Content, f: _Collector) -> None:
    haystack = " ".join((subject, content.plain, content.html_text)).lower()
    hits = [phrase for phrase in URGENT_PHRASES if phrase in haystack]
    if hits:
        f.add("urgent_language", min(15, 5 * len(hits)),
              "Urgency / account-threat wording typical of phishing", ", ".join(hits))


def _check_attachments(attachments: list[Attachment], f: _Collector) -> None:
    for att in attachments:
        ext = os.path.splitext(att.filename.lower())[1]
        if _DOUBLE_EXT_RE.search(att.filename):
            f.add("attachment_double_extension", 30,
                  "Attachment name hides an executable extension behind a document extension",
                  att.filename)
        if ext in HIGH_RISK_EXT:
            f.add("attachment_high_risk", 30, "Attachment is an executable or script type", att.filename)
        elif ext in MEDIUM_RISK_EXT:
            f.add("attachment_macro_or_html", 15,
                  "Attachment is a macro-enabled Office file or an HTML file", att.filename)
        elif ext in LOW_RISK_EXT:
            f.add("attachment_archive", 5, "Attachment is an archive (can hide its content)", att.filename)


# ------------------------------------------------------------------------- scoring


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    score = min(100, sum(f.points for f in findings))
    if score >= 50:
        return score, "likely phishing"
    if score >= 20:
        return score, "suspicious"
    return score, "low risk"


def rescore(report: Report) -> Report:
    report.findings.sort(key=lambda f: (-f.points, f.rule))
    report.score, report.verdict = score_findings(report.findings)
    return report


# --------------------------------------------------------------------------- public


def analyze_message(msg: EmailMessage) -> Report:
    f = _Collector()
    subject = str(msg.get("Subject", "") or "")
    content = _extract(msg)
    urls = _collect_urls(content)

    _check_headers(msg, f)
    for url in urls:
        _check_url(url, f)
    _check_link_text(content.anchors, f)
    _check_language(subject, content, f)
    _check_attachments(content.attachments, f)

    report = Report(
        subject=subject,
        sender=str(msg.get("From", "") or ""),
        origin_ip=origin_ip(msg),
        urls=urls,
        attachments=content.attachments,
        findings=list(f.findings.values()),
    )
    return rescore(report)


def analyze_bytes(data: bytes) -> Report:
    return analyze_message(BytesParser(policy=policy.default).parsebytes(data))


def analyze_file(path: str) -> Report:
    with open(path, "rb") as fh:
        return analyze_bytes(fh.read())
