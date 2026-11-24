from __future__ import annotations

import ipaddress
import re
from typing import Dict
from urllib.parse import urlparse, urlunparse


_SHORTENERS = {
    "bit.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "t.co",
    "tinyurl.com",
}
_SUSPICIOUS_WORDS = {
    "account",
    "confirm",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "update",
    "verify",
}


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def extract_url_features(url: str) -> Dict[str, float]:
    """Return numeric URL features used by the classifier and security checks."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    tokens = set(re.findall(r"[a-z0-9]+", f"{host} {path_and_query}"))
    try:
        ipaddress.ip_address(host)
        host_is_ip = 1.0
    except ValueError:
        host_is_ip = 0.0

    return {
        "url_length": float(len(url)),
        "host_length": float(len(host)),
        "path_length": float(len(parsed.path)),
        "dot_count": float(url.count(".")),
        "hyphen_count": float(url.count("-")),
        "at_count": float(url.count("@")),
        "question_count": float(url.count("?")),
        "equal_count": float(url.count("=")),
        "digit_ratio": float(sum(char.isdigit() for char in url) / max(len(url), 1)),
        "subdomain_count": float(max(host.count(".") - 1, 0)),
        "has_https": float(parsed.scheme.lower() == "https"),
        "has_port": float(parsed.port is not None) if parsed.hostname else 0.0,
        "host_is_ip": host_is_ip,
        "uses_shortener": float(host in _SHORTENERS),
        "suspicious_word_count": float(len(tokens & _SUSPICIOUS_WORDS)),
        "encoded_character_count": float(url.lower().count("%")),
    }


def get_host(url: str) -> str:
    return _host(url)


def normalize_model_url(url: str) -> str:
    """Normalize case-insensitive host details shared by www and apex URLs."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname = parsed.hostname
    if not hostname:
        return url

    normalized_host = hostname.lower()
    if normalized_host.startswith("www."):
        normalized_host = normalized_host[4:]
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"
    if parsed.port is not None:
        normalized_host = f"{normalized_host}:{parsed.port}"
    userinfo = f"{parsed.netloc.rsplit('@', 1)[0]}@" if "@" in parsed.netloc else ""
    return urlunparse(parsed._replace(netloc=f"{userinfo}{normalized_host}"))


def extract_feature_dicts(urls: list[str]) -> list[Dict[str, float]]:
    return [extract_url_features(url) for url in urls]
