"""Defensive phishing-signal scorer.

Analyses *supplied* text / URLs only. It never sends mail, never fetches
an arbitrary URL, and never contacts a live phishing site. All signals
are derived from the input string itself.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>'\"\)\]]+")
# [display text](href)  and  <a href="...">display text</a>
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
HTML_LINK_RE = re.compile(
    r'<a\s[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
# A bare domain-looking token in link text, e.g. "paypal.com" as text.
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}")

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "account suspended",
    "account locked", "verify now", "verify your account",
    "password expired", "payment failed", "suspended",
    "final warning", "limited time", "confirm now",
    "security alert", "unusual activity", "click here to verify",
]

SUSPICIOUS_ATTACHMENTS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar",
    ".iso", ".img", ".msi", ".hta", ".lnk",
    # NOTE: ".com" deliberately excluded — it would false-positive on
    # every ".com" domain name (e.g. paypal.com) in the message text.
}
# .zip/.rar are not malicious by themselves; they only add a small
# weight when combined with other signals, so they are handled separately.
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorturl.at", "cutt.ly", "rebrand.ly",
}

# Brands commonly impersonated. A domain that *contains* a brand name
# but is not the brand's own domain is a lookalike hint, not proof.
BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "bank", "chase", "hsbc", "cibc", "rbc",
]

# (weight, reason template)
WEIGHTS = {
    "ip_literal": 30,
    "shortener": 20,
    "punycode": 25,
    "non_ascii_host": 20,
    "mismatch": 30,
    "urgency": 10,          # per keyword, capped below
    "suspicious_attachment": 20,
    "archive_attachment": 5,
    "excessive_subdomains": 15,
    "suspicious_tld_or_port": 10,
    "lookalike_brand": 15,
    "many_links": 10,
    "at_sign_in_url": 10,
    "http_not_https": 5,
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"}


@dataclass
class Result:
    score: int
    level: str
    reasons: list = field(default_factory=list)
    urls: list = field(default_factory=list)

    def as_dict(self):
        return {
            "score": self.score,
            "risk_level": self.level,
            "reasons": self.reasons,
            "urls": self.urls,
        }


def risk_level(score: int) -> str:
    if score >= 65:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _lookalike_hint(host: str) -> str | None:
    """Return a brand name if host looks like it impersonates a brand."""
    for brand in BRANDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            # Exact brand subdomains (e.g. mail.google.com) are fine;
            # "google-security.com" or "paypal-login.net" are not.
            if host == brand or host.endswith(f".{brand}.com"):
                continue
            return brand
    return None


def _check_url(url: str, reasons: list, score_parts: list) -> None:
    host = _host(url)
    if not host:
        return
    parsed = urlparse(url)

    if _is_ip(host):
        reasons.append(f"IP-literal host: {host} (no domain name)")
        score_parts.append(WEIGHTS["ip_literal"])
    if host in SHORTENERS or host.endswith(tuple(f".{s}" for s in SHORTENERS)):
        reasons.append(f"URL shortener hides the real destination: {host}")
        score_parts.append(WEIGHTS["shortener"])
    if "xn--" in host:
        reasons.append(f"Punycode (xn--) in host: {host} — possible lookalike")
        score_parts.append(WEIGHTS["punycode"])
    if any(ord(ch) > 127 for ch in host):
        reasons.append(f"Non-ASCII characters in host: {host} — possible lookalike")
        score_parts.append(WEIGHTS["non_ascii_host"])
    if host.count(".") >= 4:  # e.g. a.b.c.d.example.com -> 5+ labels
        reasons.append(f"Excessive subdomains: {host}")
        score_parts.append(WEIGHTS["excessive_subdomains"])
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append(f"Uncommon / abuse-prone TLD: {host}")
        score_parts.append(WEIGHTS["suspicious_tld_or_port"])
    if parsed.port and parsed.port not in (80, 443):
        reasons.append(f"Non-standard port in URL: {url}")
        score_parts.append(WEIGHTS["suspicious_tld_or_port"])
    if "@" in (parsed.netloc or ""):
        reasons.append(f"'@' in URL authority (can mask the real host): {url}")
        score_parts.append(WEIGHTS["at_sign_in_url"])
    if parsed.scheme == "http":
        reasons.append(f"Plain HTTP (not HTTPS): {url}")
        score_parts.append(WEIGHTS["http_not_https"])
    brand = _lookalike_hint(host)
    if brand:
        reasons.append(f"Host mentions '{brand}' but is not the {brand} domain: {host}")
        score_parts.append(WEIGHTS["lookalike_brand"])


def _check_display_mismatch(text: str, reasons: list, score_parts: list) -> None:
    """Link text domain vs href domain mismatch."""
    pairs = []
    for display, href in MD_LINK_RE.findall(text):
        pairs.append((display, href))
    for href, display in HTML_LINK_RE.findall(text):
        pairs.append((re.sub(r"<[^>]+>", "", display), href))
    for display, href in pairs:
        shown = DOMAIN_RE.search(display)
        if not shown:
            continue
        shown_host = shown.group(0).lower()
        href_host = _host(href)
        if shown_host != href_host and not href_host.endswith(f".{shown_host}"):
            reasons.append(
                f"Display domain mismatch: text shows '{shown_host}' "
                f"but link goes to '{href_host}'"
            )
            score_parts.append(WEIGHTS["mismatch"])


def analyse(text: str) -> Result:
    """Score supplied text (raw email or a lone URL). Returns a Result."""
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    lower = text.lower()
    reasons: list = []
    score_parts: list = []

    urls = URL_RE.findall(text)
    # De-duplicate, preserving order.
    seen = set()
    unique_urls = []
    for u in urls:
        u = u.rstrip(".,;:")
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    for url in unique_urls:
        _check_url(url, reasons, score_parts)
    _check_display_mismatch(text, reasons, score_parts)

    if len(unique_urls) >= 5:
        reasons.append(f"Many links in one message: {len(unique_urls)}")
        score_parts.append(WEIGHTS["many_links"])

    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in lower]
    for kw in urgency_hits[:3]:  # cap: urgency alone never maxes the score
        reasons.append(f"Urgency / pressure language: '{kw}'")
        score_parts.append(WEIGHTS["urgency"])

    # Attachment mentions: "attachment: invoice.exe", filenames in text.
    for ext in sorted(SUSPICIOUS_ATTACHMENTS):
        if re.search(r"\b[\w\-.]+" + re.escape(ext) + r"\b", lower):
            reasons.append(f"Suspicious attachment type mentioned: *{ext}")
            score_parts.append(WEIGHTS["suspicious_attachment"])
    for ext in sorted(ARCHIVE_EXTENSIONS):
        if re.search(r"\b[\w\-.]+" + re.escape(ext) + r"\b", lower):
            reasons.append(f"Archive attachment mentioned: *{ext} (check before opening)")
            score_parts.append(WEIGHTS["archive_attachment"])

    score = min(100, sum(score_parts))
    if not reasons:
        reasons.append("No phishing signals found in the supplied text.")
    return Result(score=score, level=risk_level(score), reasons=reasons, urls=unique_urls)
