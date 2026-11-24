from __future__ import annotations

import html
import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import joblib

from .features import extract_url_features, get_host, normalize_model_url


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str


TRUSTED_INSTITUTIONAL_HOSTS = frozenset({"ug.nsuk.edu.ng"})
KNOWN_PHISHING_DOMAINS = frozenset({
    "amaz0n.com",
    "amaiz0n.com",
    "amazn.com",
    "paypa1.com",
    "paypal-confirm.com",
    "secure-paypal.com",
    "verify-amazon.com",
    "update-gmail.com",
    "apple-verify.com",
    "microsoft-confirm.com",
    "netflix-confirm.com",
    "bank-verify.com",
    "secure-login.com",
    "account-verify.net",
    "login-facebook.com",
    "confirm-identity.com",
    "verify-account.net",
    "security-alert.com",
    "urgent-verify.net",
    "account-suspended.net",
    "update-account.com",
    "verify-identity.net",
    "confirm-credentials.com",
})


class PhishingAnalyzer:
    """Loads a trained URL model and adds transparent HTML security findings."""

    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Model file does not exist: {self.model_path}")
        self.model = joblib.load(self.model_path)
        digest = hashlib.sha256()
        with self.model_path.open("rb") as model_file:
            for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
                digest.update(chunk)
        self.model_version = digest.hexdigest()[:12]

    def analyze(self, url: str, page_html: Optional[str] = None) -> Dict[str, Any]:
        url = _validate_url(url)
        probabilities = self.model.predict_proba([normalize_model_url(url)])[0]
        classes = list(self.model.classes_)
        phishing_probability = float(probabilities[classes.index(1)])
        probability = phishing_probability
        findings = self._website_findings(url, page_html)
        rule_score = min(sum({"low": 10, "medium": 20, "high": 35}[f.severity] for f in findings), 100)
        risk_score = round(max(probability * 100, rule_score), 2)

        model_prediction = "phishing" if probability >= 0.5 else "legitimate"
        trusted_domain = _is_trusted_institutional_host(url)
        security_rule = any(
            finding.code == "nsuk_lookalike"
            or (finding.code == "brand_lookalike" and finding.severity == "high")
            or finding.code == "known_phishing_domain"
            for finding in findings
        )
        prediction = "legitimate" if trusted_domain else "phishing" if security_rule else model_prediction
        return {
            "url": url,
            "prediction": prediction,
            "label": prediction,
            "classification_source": "trusted_institutional_domain" if trusted_domain else "security_rule" if security_rule else "ai_model",
            "phishing_probability": round(probability, 4),
            "risk_score": risk_score,
            "findings_risk_score": rule_score,
            "model_version": self.model_version,
            "ai_model": self.model_info,
            "findings": [asdict(finding) for finding in findings],
        }

    @property
    def model_info(self) -> Dict[str, Any]:
        named_steps = getattr(self.model, "named_steps", {})
        classifier = named_steps.get("classifier")
        if classifier is None:
            return {"type": type(self.model).__name__}
        if hasattr(classifier, "hidden_layer_sizes"):
            return {
                "type": "supervised_neural_network",
                "algorithm": "multilayer_perceptron",
                "architecture": [classifier.n_features_in_, *classifier.hidden_layer_sizes, 1],
                "activation": classifier.activation,
                "training_iterations": classifier.n_iter_,
            }
        return {"type": "supervised_classifier", "algorithm": type(classifier).__name__}

    def _website_findings(self, url: str, page_html: Optional[str]) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(url if "://" in url else f"http://{url}")
        features = extract_url_features(url)
        if parsed.scheme.lower() != "https":
            findings.append(Finding("no_https", "medium", "The page does not use HTTPS."))
        if features["host_is_ip"]:
            findings.append(Finding("ip_host", "high", "The hostname is an IP address rather than a domain."))
        if features["uses_shortener"]:
            findings.append(Finding("url_shortener", "medium", "A URL-shortening service hides the destination."))
        if features["at_count"]:
            findings.append(Finding("at_symbol", "high", "The URL contains '@', which can obscure the real host."))
        if features["suspicious_word_count"] >= 2:
            findings.append(Finding("suspicious_terms", "medium", "The URL contains multiple account or verification terms."))
        known_phishing_domain = _known_phishing_hostname(url)
        if known_phishing_domain:
            findings.append(Finding(
                "known_phishing_domain",
                "high",
                f"The hostname {known_phishing_domain} exactly matches an entry in the known-phishing domain list.",
            ))
        if _is_nsuk_lookalike_host(url):
            findings.append(Finding(
                "nsuk_lookalike",
                "high",
                "This hostname resembles the official NSUK undergraduate portal domain. Similarity alone does not confirm malicious intent; verify the address using an official NSUK source.",
            ))
        brand = _brand_lookalike(url)
        if brand:
            findings.append(Finding(
                "brand_lookalike",
                "high",
                f"The hostname resembles the well-known brand {brand}.",
            ))
        if page_html:
            findings.extend(_html_findings(url, page_html))
        return findings


def _validate_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url must be a non-empty string")
    url = url.strip()
    if len(url) > 2048 or any(character.isspace() or ord(character) < 32 for character in url):
        raise ValueError("url must be at most 2048 characters and contain no whitespace")
    normalized_url = url if "://" in url else f"https://{url}"
    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("url must contain a valid HTTP or HTTPS hostname") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("url must contain a valid HTTP or HTTPS hostname")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("url must contain a valid hostname") from exc
        labels = ascii_hostname.split(".")
        if (
            ascii_hostname.lower() != "localhost"
            and (
                len(ascii_hostname) > 253
                or len(labels) < 2
                or len(labels[-1]) < 2
                or any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in labels)
            )
        ):
            raise ValueError("url must contain a valid hostname")
    return normalized_url


def _is_trusted_institutional_host(url: str) -> bool:
    hostname = (urlparse(url).hostname or "").casefold().rstrip(".")
    return hostname in TRUSTED_INSTITUTIONAL_HOSTS


def _known_phishing_hostname(url: str) -> Optional[str]:
    hostname = (urlparse(url).hostname or "").casefold().rstrip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname if hostname in KNOWN_PHISHING_DOMAINS else None


def _is_nsuk_lookalike_host(url: str) -> bool:
    hostname = (urlparse(url).hostname or "").casefold().rstrip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]

    official_hostname = "ug.nsuk.edu.ng"
    if hostname == official_hostname:
        return False
    if hostname.startswith(f"{official_hostname}."):
        return True

    labels = hostname.split(".")
    for index in range(len(labels) - 3):
        candidate = labels[index:index + 4]
        if candidate[2:] == ["edu", "ng"] and (
            _hostname_label_is_near_match(candidate[0], "ug")
            and _hostname_label_is_near_match(candidate[1], "nsuk")
            and candidate[:2] != ["ug", "nsuk"]
        ):
            return True
    return False


def _hostname_label_is_near_match(candidate: str, expected: str) -> bool:
    if abs(len(candidate) - len(expected)) > 1:
        return False
    if len(candidate) == len(expected):
        differences = [index for index, (left, right) in enumerate(zip(candidate, expected)) if left != right]
        if len(differences) <= 1:
            return True
        return (
            len(differences) == 2
            and differences[1] == differences[0] + 1
            and candidate[differences[0]] == expected[differences[1]]
            and candidate[differences[1]] == expected[differences[0]]
        )

    shorter, longer = sorted((candidate, expected), key=len)
    short_index = 0
    long_index = 0
    skipped = False
    while short_index < len(shorter) and long_index < len(longer):
        if shorter[short_index] == longer[long_index]:
            short_index += 1
            long_index += 1
        elif skipped:
            return False
        else:
            skipped = True
            long_index += 1
    return True


def _brand_lookalike(url: str) -> Optional[str]:
    host = get_host(url).rstrip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return None
    candidate = labels[-2].lower()
    normalized_candidate = candidate.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "8": "b"}))
    brands = {
        "amazon": "Amazon",
        "apple": "Apple",
        "facebook": "Facebook",
        "google": "Google",
        "microsoft": "Microsoft",
        "netflix": "Netflix",
        "paypal": "PayPal",
        "youtube": "YouTube",
    }
    for brand, display_name in brands.items():
        if candidate != brand and (
            normalized_candidate == brand
            or SequenceMatcher(None, normalized_candidate, brand).ratio() >= 0.82
        ):
            return display_name
    return None


def _html_findings(url: str, page_html: str) -> List[Finding]:
    findings: List[Finding] = []
    source = html.unescape(page_html)
    page_host = get_host(url)
    password_forms = re.findall(r"<input\b[^>]*type\s*=\s*['\"]?password", source, re.I)
    if password_forms and urlparse(url if "://" in url else f"http://{url}").scheme.lower() != "https":
        findings.append(Finding("password_over_http", "high", "A password field is present on a non-HTTPS page."))
    hidden_elements = re.findall(r"(?:display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*['\"]hidden)", source, re.I)
    if len(hidden_elements) >= 3:
        findings.append(Finding("hidden_content", "low", "The page contains several hidden elements."))
    external_forms = re.findall(r"<form\b[^>]*action\s*=\s*['\"]([^'\"]+)", source, re.I)
    for action in external_forms:
        action_host = get_host(action) if "://" in action else page_host
        if action_host and action_host != page_host:
            findings.append(Finding("external_form_target", "high", "A form submits data to another hostname."))
            break
    if re.search(r"<iframe\b", source, re.I):
        findings.append(Finding("iframe_present", "low", "The page embeds an iframe; review its source."))
    return findings
