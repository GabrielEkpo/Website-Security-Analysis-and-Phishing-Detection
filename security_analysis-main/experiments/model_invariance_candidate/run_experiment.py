from __future__ import annotations

import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import joblib
import numpy as np
from scipy.sparse import issparse
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from phishing_detector.features import extract_feature_dicts, normalize_model_url


PROJECT_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = Path(__file__).resolve().parent
PRODUCTION_MODEL_PATH = PROJECT_DIR / "artifacts" / "phishing_model.joblib"
SOURCE_DATASET_PATH = PROJECT_DIR.parent / "phiusiil+phishing+url+dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
NIGERIAN_DATASET_PATH = PROJECT_DIR / "dataset" / "nigerian_websites_dataset.csv"
OUTPUT_FILES = (
    "candidate_model.joblib",
    "evaluation_report.json",
    "evaluation_report.md",
    "split_manifest.json",
    "heldout_test_set.csv",
)

TEST_SIZE = 0.2
SPLIT_RANDOM_STATE = 42
CLASSIFIER_RANDOM_STATE = 42
FORMATTING_PAIR_HOST_LIMIT = 2000
FORMATTING_TOLERANCE = 1e-12
CALIBRATION_BIN_COUNT = 10


def canonicalize_candidate_url(url: str) -> str:
    """Normalize declared formatting equivalents; preserve meaningful URL parts."""
    value = url.strip()
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Candidate URL must have an HTTP(S) hostname: {url!r}")

    hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if not hostname:
        raise ValueError(f"Candidate URL has an empty hostname: {url!r}")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Candidate URL has an invalid port: {url!r}") from exc

    if port is not None and not (scheme == "https" and port == 443) and not (scheme == "http" and port == 80):
        hostname = f"{hostname}:{port}"

    userinfo = f"{parsed.netloc.rsplit('@', 1)[0]}@" if "@" in parsed.netloc else ""
    netloc = f"{userinfo}{hostname}"
    path = "" if parsed.path == "/" else parsed.path
    return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))


def canonicalize_candidate_urls(urls: list[str]) -> list[str]:
    return [canonicalize_candidate_url(url) for url in urls]


def log1p_sparse_features(matrix: Any) -> Any:
    if issparse(matrix):
        return np.log1p(matrix)
    return np.log1p(np.asarray(matrix, dtype=float))


def grouping_hostname(url: str) -> str:
    """Group case, final-dot, and www/apex aliases by exact hostname."""
    value = url.strip()
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError(f"Dataset URL has no hostname: {url!r}")
    hostname = parsed.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
    return hostname[4:] if hostname.startswith("www.") else hostname


def raw_label_to_phishing(raw_label: str) -> int:
    if raw_label == "0":
        return 1
    if raw_label == "1":
        return 0
    raise ValueError(f"Unexpected raw PhiUSIIL label: {raw_label!r}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_nigerian_urls() -> tuple[list[str], set[str], dict[str, Any]]:
    urls: list[str] = []
    labels: list[int] = []
    groups: set[str] = set()
    with NIGERIAN_DATASET_PATH.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        columns = {name.strip().lower(): name for name in (reader.fieldnames or [])}
        url_column = columns.get("url")
        label_column = columns.get("label")
        if not url_column or not label_column:
            raise ValueError("Nigerian check CSV must contain URL and Label columns")
        for row_number, row in enumerate(reader, start=2):
            url = (row.get(url_column) or "").strip()
            raw_label = (row.get(label_column) or "").strip()
            if not url or raw_label != "1":
                raise ValueError(f"Nigerian check row {row_number} is not a labeled legitimate URL")
            urls.append(url)
            labels.append(raw_label_to_phishing(raw_label))
            groups.add(grouping_hostname(url))
    details = {
        "rows": len(urls),
        "raw_label_counts": dict(Counter("1" for _ in urls)),
        "expected_class_counts": {"legitimate": len(urls), "phishing": 0},
        "host_groups_reserved_out_of_main_experiment": sorted(groups),
    }
    return urls, groups, details


def load_source_rows(reserved_hosts: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    raw_counts: Counter[str] = Counter()
    excluded_rows = 0
    excluded_host_counts: Counter[str] = Counter()
    with SOURCE_DATASET_PATH.open(newline="", encoding="utf-8-sig", errors="replace") as source:
        reader = csv.DictReader(source)
        columns = {name.strip().lower(): name for name in (reader.fieldnames or [])}
        url_column = columns.get("url")
        label_column = columns.get("label")
        if not url_column or not label_column:
            raise ValueError("PhiUSIIL source CSV must contain URL and label columns")
        for source_row_number, row in enumerate(reader, start=2):
            url = (row.get(url_column) or "").strip()
            raw_label = (row.get(label_column) or "").strip()
            if not url:
                raise ValueError(f"PhiUSIIL row {source_row_number} has an empty URL")
            phishing_label = raw_label_to_phishing(raw_label)
            group = grouping_hostname(url)
            raw_counts[raw_label] += 1
            if group in reserved_hosts:
                excluded_rows += 1
                excluded_host_counts[group] += 1
                continue
            rows.append({
                "source_row_number": source_row_number,
                "url": url,
                "raw_label": raw_label,
                "label": phishing_label,
                "group": group,
            })
    return rows, {
        "source_rows": sum(raw_counts.values()),
        "raw_label_counts": dict(raw_counts),
        "expected_class_counts": {
            "legitimate": raw_counts["1"],
            "phishing": raw_counts["0"],
        },
        "rows_reserved_out_for_nigerian_host_overlap": excluded_rows,
        "overlapping_nigerian_host_groups": dict(sorted(excluded_host_counts.items())),
        "rows_available_for_domain_split": len(rows),
    }


def deduplicate_partition(
    rows: list[dict[str, Any]], partition: str
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    by_canonical_url: dict[str, dict[str, Any]] = {}
    conflicting_urls: set[str] = set()
    dropped_duplicates = 0
    for row in rows:
        canonical_url = canonicalize_candidate_url(row["url"])
        existing = by_canonical_url.get(canonical_url)
        if existing and existing["label"] != row["label"]:
            conflicting_urls.add(canonical_url)
        elif existing:
            dropped_duplicates += 1
        else:
            by_canonical_url[canonical_url] = {**row, "candidate_canonical_url": canonical_url}
    clean_rows = [row for key, row in by_canonical_url.items() if key not in conflicting_urls]
    conflict_rows = sum(
        1 for row in rows if canonicalize_candidate_url(row["url"]) in conflicting_urls
    )
    return clean_rows, {
        "conflicting_canonical_urls_excluded": len(conflicting_urls),
        "rows_excluded_for_conflicting_canonical_labels": conflict_rows,
        "same_label_duplicates_collapsed": dropped_duplicates,
    }


def build_candidate_model() -> Pipeline:
    url_characters = Pipeline([
        ("canonicalize", FunctionTransformer(canonicalize_candidate_urls, validate=False)),
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            min_df=1,
            max_features=12000,
        )),
    ])
    url_properties = Pipeline([
        ("canonicalize", FunctionTransformer(canonicalize_candidate_urls, validate=False)),
        ("extract", FunctionTransformer(extract_feature_dicts, validate=False)),
        ("vectorize", DictVectorizer()),
        ("log1p", FunctionTransformer(log1p_sparse_features, validate=False, accept_sparse=True)),
        ("scale", StandardScaler(with_mean=False)),
    ])
    return Pipeline([
        ("features", FeatureUnion([
            ("url_characters", url_characters),
            ("url_properties", url_properties),
        ])),
        ("classifier", LogisticRegression(
            solver="liblinear",
            max_iter=200,
            random_state=CLASSIFIER_RANDOM_STATE,
        )),
    ])


def positive_class_probabilities(model: Pipeline, urls: list[str], normalizer=None) -> np.ndarray:
    model_urls = [normalizer(url) for url in urls] if normalizer else urls
    class_index = list(model.classes_).index(1)
    return model.predict_proba(model_urls)[:, class_index]


def binary_metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict[str, Any]:
    predictions = (probabilities >= 0.5).astype(int)
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    calibration_bins = []
    bin_ids = np.minimum((probabilities * CALIBRATION_BIN_COUNT).astype(int), CALIBRATION_BIN_COUNT - 1)
    for bin_index in range(CALIBRATION_BIN_COUNT):
        selected = bin_ids == bin_index
        count = int(selected.sum())
        if count:
            calibration_bins.append({
                "lower_probability": bin_index / CALIBRATION_BIN_COUNT,
                "upper_probability": (bin_index + 1) / CALIBRATION_BIN_COUNT,
                "count": count,
                "mean_probability": float(probabilities[selected].mean()),
                "observed_phishing_rate": float(labels[selected].mean()),
            })
    return {
        "threshold": 0.5,
        "false_positive_rate": float(false_positive / max(true_negative + false_positive, 1)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "confusion_matrix_labels_0_legitimate_1_phishing": matrix.tolist(),
        "counts": {
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
        "brier_score": float(brier_score_loss(labels, probabilities)),
        "log_loss": float(log_loss(labels, probabilities, labels=[0, 1])),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "calibration_bins_equal_width": calibration_bins,
    }


def formatting_variants(host: str) -> dict[str, str]:
    base = f"https://{host}"
    parsed = urlsplit(base)
    uppercase_host = parsed.hostname.upper() if parsed.hostname else host.upper()
    return {
        "base": base,
        "uppercase_hostname": urlunsplit(("https", uppercase_host, "", "", "")),
        "trailing_hostname_dot": urlunsplit(("https", f"{parsed.hostname}.", "", "", "")),
        "root_slash": urlunsplit(("https", parsed.hostname or host, "/", "", "")),
        "explicit_default_port_443": urlunsplit(("https", f"{parsed.hostname}:443", "", "", "")),
        "www_host_variant_not_assumed_equivalent": urlunsplit(("https", f"www.{parsed.hostname or host}", "", "", "")),
    }


def formatting_pair_metrics(
    hosts: list[str], production_model: Pipeline, candidate_model: Pipeline
) -> dict[str, Any]:
    selected_hosts = sorted(hosts)
    if len(selected_hosts) > FORMATTING_PAIR_HOST_LIMIT:
        selected_hosts = sorted(random.Random(SPLIT_RANDOM_STATE).sample(selected_hosts, FORMATTING_PAIR_HOST_LIMIT))
    variants_by_host = {host: formatting_variants(host) for host in selected_hosts}
    variant_names = list(next(iter(variants_by_host.values())).keys()) if variants_by_host else []
    urls_by_variant = {
        name: [variants_by_host[host][name] for host in selected_hosts]
        for name in variant_names
    }
    production_scores = {
        name: positive_class_probabilities(production_model, urls, normalizer=normalize_model_url)
        for name, urls in urls_by_variant.items()
    }
    candidate_scores = {
        name: positive_class_probabilities(candidate_model, urls)
        for name, urls in urls_by_variant.items()
    }
    expected_equivalent_names = [
        "uppercase_hostname",
        "trailing_hostname_dot",
        "root_slash",
        "explicit_default_port_443",
    ]
    results: dict[str, Any] = {
        "sampled_heldout_host_groups": len(selected_hosts),
        "expected_equivalent_variants": expected_equivalent_names,
        "www_host_variant_is_reported_separately_and_not_assumed_equivalent": True,
        "tolerance": FORMATTING_TOLERANCE,
        "models": {},
    }
    for model_name, scores in (("production", production_scores), ("candidate", candidate_scores)):
        baseline = scores["base"]
        pair_stats = {}
        per_host_spreads = []
        for variant_name in expected_equivalent_names:
            deltas = np.abs(scores[variant_name] - baseline)
            pair_stats[variant_name] = {
                "exact_probability_matches": int((deltas <= FORMATTING_TOLERANCE).sum()),
                "tested_pairs": len(deltas),
                "consistency_rate": float((deltas <= FORMATTING_TOLERANCE).mean()) if len(deltas) else 1.0,
                "max_absolute_probability_delta": float(deltas.max()) if len(deltas) else 0.0,
                "mean_absolute_probability_delta": float(deltas.mean()) if len(deltas) else 0.0,
            }
            per_host_spreads.append(scores[variant_name])
        equivalent_matrix = np.vstack([baseline, *per_host_spreads]) if len(baseline) else np.empty((0, 0))
        equivalent_ranges = equivalent_matrix.max(axis=0) - equivalent_matrix.min(axis=0) if len(baseline) else np.array([])
        www_deltas = np.abs(scores["www_host_variant_not_assumed_equivalent"] - baseline)
        results["models"][model_name] = {
            "pair_results": pair_stats,
            "all_equivalent_forms_consistent": bool(np.all(equivalent_ranges <= FORMATTING_TOLERANCE)),
            "max_probability_range_across_equivalent_forms": float(equivalent_ranges.max()) if len(equivalent_ranges) else 0.0,
            "www_variant_mean_absolute_delta_not_an_invariance_test": float(www_deltas.mean()) if len(www_deltas) else 0.0,
            "www_variant_max_absolute_delta_not_an_invariance_test": float(www_deltas.max()) if len(www_deltas) else 0.0,
        }
    results["examples"] = {
        host: {
            variant: {
                "url": variants_by_host[host][variant],
                "production_probability": float(production_scores[variant][selected_hosts.index(host)]),
                "candidate_probability": float(candidate_scores[variant][selected_hosts.index(host)]),
            }
            for variant in variant_names
        }
        for host in selected_hosts[:10]
    }
    return results


def save_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        json.dump(payload, destination, indent=2, sort_keys=True)
        destination.write("\n")


def render_report(report: dict[str, Any]) -> str:
    main = report["main_evaluation"]
    production = main["production"]
    candidate = main["candidate"]
    formatting = report["formatting_pair_consistency"]
    nigerian = report["nigerian_separate_check"]
    lines = [
        "# Isolated URL Invariance Candidate Experiment",
        "",
        "## Isolation and split",
        "",
        f"- Production fingerprint before/after: `{report['production_artifact']['sha256_before']}` / `{report['production_artifact']['sha256_after']}`.",
        f"- Source dataset SHA-256: `{report['source_dataset_sha256']}`.",
        f"- Original rows: {report['dataset']['source_rows']}; rows reserved out for the separate Nigerian check: {report['dataset']['rows_reserved_out_for_nigerian_host_overlap']}; rows used for split: {report['dataset']['rows_available_for_domain_split']}.",
        f"- Split: GroupShuffleSplit, seed {report['split']['random_state']}, held-out fraction {report['split']['test_size']:.0%}; exact-host groups, lowercased with terminal dot and leading www removed. Hostname groups are disjoint; this is not eTLD+1 grouping.",
        f"- Candidate training examples: {report['split']['train_rows']}; held-out rows: {report['split']['test_rows']}; training hosts: {report['split']['train_host_groups']}; held-out hosts: {report['split']['test_host_groups']}.",
        f"- Candidate-canonical duplicate handling: train excluded {report['split']['train_canonical_url_deduplication']['rows_excluded_for_conflicting_canonical_labels']} rows with conflicting labels; held-out excluded {report['split']['heldout_canonical_url_deduplication']['rows_excluded_for_conflicting_canonical_labels']} such rows. Same-label duplicates were collapsed only within their assigned partition.",
        "- The held-out host list and evaluated held-out rows are frozen in `split_manifest.json` and `heldout_test_set.csv`.",
        "- No Nigerian rows were added to either main partition. Any Nigerian host already present in PhiUSIIL was excluded from both partitions.",
        "",
        "## Candidate changes",
        "",
        "- Retains LogisticRegression and full-URL character TF-IDF (2–5 character n-grams, up to 12,000 features).",
        "- Candidate-only canonicalization lowercases IDNA hostnames, removes a final hostname dot, collapses only an empty root path and `/`, and removes scheme-default ports (`https:443`, `http:80`). It preserves scheme, non-root paths, query, fragment, non-default ports, and `www`.",
        "- Candidate structured branch applies `log1p` then `StandardScaler(with_mean=False)`; scaler and vectorizer are fitted only on training groups.",
        "- No feature-selection, hyperparameter search, Nigerian augmentation, security-rule, threshold, or production changes were made.",
        "",
        "## Main held-out metrics",
        "",
        "| Metric | Frozen production | Candidate |",
        "|---|---:|---:|",
        f"| False-positive rate | {production['false_positive_rate']:.6f} | {candidate['false_positive_rate']:.6f} |",
        f"| Precision | {production['precision']:.6f} | {candidate['precision']:.6f} |",
        f"| Recall | {production['recall']:.6f} | {candidate['recall']:.6f} |",
        f"| F1 | {production['f1']:.6f} | {candidate['f1']:.6f} |",
        f"| Brier score | {production['brier_score']:.6f} | {candidate['brier_score']:.6f} |",
        f"| Log loss | {production['log_loss']:.6f} | {candidate['log_loss']:.6f} |",
        f"| ROC AUC | {production['roc_auc']:.6f} | {candidate['roc_auc']:.6f} |",
        "",
        f"Confusion matrices use label order `[0=legitimate, 1=phishing]`. Production: `{production['confusion_matrix_labels_0_legitimate_1_phishing']}`. Candidate: `{candidate['confusion_matrix_labels_0_legitimate_1_phishing']}`.",
        "",
        "Calibration tables and full confusion counts are in `evaluation_report.json`.",
        "",
        "## Formatting-pair consistency",
        "",
        f"Tested {formatting['sampled_heldout_host_groups']} deterministic held-out host groups against uppercase, terminal-dot, root-slash, and explicit default-HTTPS-port forms. `www` was separately reported, not assumed equivalent.",
        "",
        f"- Production all-forms consistent within tolerance: `{formatting['models']['production']['all_equivalent_forms_consistent']}`; max range `{formatting['models']['production']['max_probability_range_across_equivalent_forms']:.12g}`.",
        f"- Candidate all-forms consistent within tolerance: `{formatting['models']['candidate']['all_equivalent_forms_consistent']}`; max range `{formatting['models']['candidate']['max_probability_range_across_equivalent_forms']:.12g}`.",
        "",
        "Per-variant pair counts and deltas, plus example hosts, are in `evaluation_report.json`.",
        "",
        "## Separate Nigerian legitimate-domain check",
        "",
        f"- URLs: {nigerian['rows']}; raw label `1` for every row, mapped to legitimate. This set was not used for training, main evaluation, feature fitting, or tuning.",
        f"- Production correct legitimate classifications: {nigerian['production_correct']}/{nigerian['rows']}.",
        f"- Candidate correct legitimate classifications: {nigerian['candidate_correct']}/{nigerian['rows']}.",
        "- This small all-legitimate set is a separate check, not evidence of generalization.",
        "",
        "## Security regressions and disposition",
        "",
        f"- Existing Django tests: {report['security_regression_tests']['status']} ({report['security_regression_tests']['summary']}).",
        "- The candidate was never placed at the production model path and is not integrated or deployed.",
        "- Promotion status: NOT PROMOTED. The experiment is evidence for review only; production remains the baseline artifact.",
        "- Hostname grouping does not fully prevent sibling-subdomain leakage because no Public Suffix List source was available locally.",
        "",
    ]
    return "\n".join(lines)


def run() -> None:
    if not SOURCE_DATASET_PATH.is_file() or not NIGERIAN_DATASET_PATH.is_file() or not PRODUCTION_MODEL_PATH.is_file():
        raise FileNotFoundError("Required source dataset, Nigerian check, or production model is unavailable")
    existing_outputs = [OUTPUT_DIR / name for name in OUTPUT_FILES if (OUTPUT_DIR / name).exists()]
    if existing_outputs:
        raise FileExistsError(
            "Refusing to overwrite previous experiment outputs: "
            + ", ".join(str(path) for path in existing_outputs)
        )

    production_sha_before = file_sha256(PRODUCTION_MODEL_PATH)
    production_model = joblib.load(PRODUCTION_MODEL_PATH)
    if type(production_model.named_steps.get("classifier")).__name__ != "LogisticRegression":
        raise TypeError("Expected the approved production LogisticRegression artifact")

    nigerian_urls, nigerian_reserved_hosts, nigerian_metadata = read_nigerian_urls()
    rows, dataset_metadata = load_source_rows(nigerian_reserved_hosts)
    labels = np.asarray([row["label"] for row in rows], dtype=int)
    groups = np.asarray([row["group"] for row in rows], dtype=object)
    if len(set(labels.tolist())) != 2:
        raise ValueError("Both phishing and legitimate examples must remain after Nigerian-host reservation")

    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=SPLIT_RANDOM_STATE)
    train_indices, test_indices = next(splitter.split(np.zeros(len(rows)), labels, groups))
    train_rows, train_deduplication = deduplicate_partition(
        [rows[index] for index in train_indices], "train"
    )
    test_rows, test_deduplication = deduplicate_partition(
        [rows[index] for index in test_indices], "test"
    )
    train_hosts = {row["group"] for row in train_rows}
    test_hosts = {row["group"] for row in test_rows}
    if train_hosts & test_hosts:
        raise AssertionError("Hostname leakage found between candidate training and held-out sets")
    if train_hosts & nigerian_reserved_hosts or test_hosts & nigerian_reserved_hosts:
        raise AssertionError("Nigerian check host leaked into main experiment")

    train_urls = [row["url"] for row in train_rows]
    train_labels = np.asarray([row["label"] for row in train_rows], dtype=int)
    test_urls = [row["url"] for row in test_rows]
    test_labels = np.asarray([row["label"] for row in test_rows], dtype=int)
    if len(set(train_labels.tolist())) != 2 or len(set(test_labels.tolist())) != 2:
        raise ValueError("Frozen hostname split must contain both classes in train and held-out partitions")

    candidate_model = build_candidate_model()
    candidate_model.fit(train_urls, train_labels)

    production_probabilities = positive_class_probabilities(
        production_model,
        test_urls,
        normalizer=normalize_model_url,
    )
    candidate_probabilities = positive_class_probabilities(candidate_model, test_urls)
    main_evaluation = {
        "heldout_rows": len(test_rows),
        "heldout_host_groups": len(test_hosts),
        "production": binary_metrics(test_labels, production_probabilities),
        "candidate": binary_metrics(test_labels, candidate_probabilities),
    }

    formatting = formatting_pair_metrics(sorted(test_hosts), production_model, candidate_model)
    nigerian_labels = np.zeros(len(nigerian_urls), dtype=int)
    nigerian_production_probabilities = positive_class_probabilities(
        production_model,
        nigerian_urls,
        normalizer=normalize_model_url,
    )
    nigerian_candidate_probabilities = positive_class_probabilities(candidate_model, nigerian_urls)
    nigerian = {
        **nigerian_metadata,
        "production_correct": int(((nigerian_production_probabilities < 0.5) == (nigerian_labels == 0)).sum()),
        "candidate_correct": int(((nigerian_candidate_probabilities < 0.5) == (nigerian_labels == 0)).sum()),
        "production_probabilities": [float(value) for value in nigerian_production_probabilities],
        "candidate_probabilities": [float(value) for value in nigerian_candidate_probabilities],
    }

    production_sha_after = file_sha256(PRODUCTION_MODEL_PATH)
    if production_sha_before != production_sha_after:
        raise RuntimeError("Production model fingerprint changed during isolated experiment")

    manifest = {
        "source_dataset_sha256": file_sha256(SOURCE_DATASET_PATH),
        "nigerian_dataset_sha256": file_sha256(NIGERIAN_DATASET_PATH),
        "split_method": "GroupShuffleSplit by lowercased exact hostname, stripping terminal dot and leading www for grouping only",
        "random_state": SPLIT_RANDOM_STATE,
        "test_size": TEST_SIZE,
        "registrable_domain_split": False,
        "public_suffix_list_available": False,
        "nigerian_reserved_host_groups": sorted(nigerian_reserved_hosts),
        "train_host_groups": sorted(train_hosts),
        "heldout_host_groups": sorted(test_hosts),
        "train_rows_after_candidate_canonical_deduplication": len(train_rows),
        "heldout_rows_after_candidate_canonical_deduplication": len(test_rows),
        "train_canonical_url_deduplication": train_deduplication,
        "heldout_canonical_url_deduplication": test_deduplication,
        "production_sha256_before": production_sha_before,
        "production_sha256_after": production_sha_after,
    }
    report = {
        "experiment": "isolated_url_invariance_candidate",
        "promotion_status": "NOT_PROMOTED",
        "production_artifact": {
            "path": str(PRODUCTION_MODEL_PATH.relative_to(PROJECT_DIR)),
            "sha256_before": production_sha_before,
            "sha256_after": production_sha_after,
            "unchanged": production_sha_before == production_sha_after,
        },
        "source_dataset_sha256": manifest["source_dataset_sha256"],
        "dataset": dataset_metadata,
        "split": {
            "method": manifest["split_method"],
            "random_state": SPLIT_RANDOM_STATE,
            "test_size": TEST_SIZE,
            "train_rows": len(train_rows),
            "test_rows": len(test_rows),
            "train_host_groups": len(train_hosts),
            "test_host_groups": len(test_hosts),
            "host_overlap": len(train_hosts & test_hosts),
            "train_canonical_url_deduplication": train_deduplication,
            "heldout_canonical_url_deduplication": test_deduplication,
            "registrable_domain_split": False,
            "public_suffix_list_available": False,
        },
        "candidate_design": {
            "classifier": "LogisticRegression(solver='liblinear', max_iter=200, random_state=42)",
            "character_branch": "TfidfVectorizer(analyzer='char', ngram_range=(2, 5), min_df=1, max_features=12000)",
            "structured_branch": "extract_url_features -> DictVectorizer -> log1p -> StandardScaler(with_mean=False)",
            "candidate_canonicalization": "lowercase IDNA host, strip final dot, collapse root slash, remove http:80/https:443; preserve scheme, non-root path, query, fragment, non-default port, and www",
            "fit_scope": "training hostname groups only",
            "hyperparameter_tuning": False,
            "nigerian_data_augmentation": False,
        },
        "main_evaluation": main_evaluation,
        "formatting_pair_consistency": formatting,
        "nigerian_separate_check": nigerian,
        "security_regression_tests": {
            "status": "NOT_RUN_BY_EXPERIMENT_SCRIPT",
            "summary": "Run manage.py test tests separately; this runner does not alter application rules or thresholds.",
        },
        "limitations": [
            "Exact hostname grouping is not registrable-domain grouping and may allow sibling-subdomain leakage.",
            "Formatting-pair evaluation uses up to 2000 deterministic held-out hostname representatives.",
            "No numeric promotion tolerance for held-out metric changes was approved; candidate is never auto-promoted.",
            "The Nigerian set is all legitimate and is a separate check, not generalization evidence.",
        ],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(candidate_model, OUTPUT_DIR / "candidate_model.joblib")
    save_json(OUTPUT_DIR / "split_manifest.json", manifest)
    save_json(OUTPUT_DIR / "evaluation_report.json", report)
    with (OUTPUT_DIR / "heldout_test_set.csv").open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=["source_row_number", "url", "raw_label", "expected_phishing_label", "hostname_group"])
        writer.writeheader()
        for row in test_rows:
            writer.writerow({
                "source_row_number": row["source_row_number"],
                "url": row["url"],
                "raw_label": row["raw_label"],
                "expected_phishing_label": row["label"],
                "hostname_group": row["group"],
            })
    report["security_regression_tests"] = {
        "status": "RUN_SEPARATELY",
        "summary": "The runner deliberately does not run or modify application security regression tests.",
    }
    (OUTPUT_DIR / "evaluation_report.md").write_text(render_report(report), encoding="utf-8", newline="\n")
    save_json(OUTPUT_DIR / "evaluation_report.json", report)

    print(json.dumps({
        "output_dir": str(OUTPUT_DIR),
        "production_sha256_before": production_sha_before,
        "production_sha256_after": production_sha_after,
        "split": report["split"],
        "main_metrics": {
            name: {
                "fpr": value["false_positive_rate"],
                "precision": value["precision"],
                "recall": value["recall"],
                "f1": value["f1"],
                "brier": value["brier_score"],
                "confusion_matrix": value["confusion_matrix_labels_0_legitimate_1_phishing"],
            }
            for name, value in main_evaluation.items()
            if isinstance(value, dict)
        },
        "formatting_consistency": {
            name: {
                "all_equivalent_forms_consistent": details["all_equivalent_forms_consistent"],
                "max_probability_range": details["max_probability_range_across_equivalent_forms"],
            }
            for name, details in formatting["models"].items()
        },
        "nigerian_check": {
            "rows": nigerian["rows"],
            "production_correct": nigerian["production_correct"],
            "candidate_correct": nigerian["candidate_correct"],
        },
        "candidate_path_length_coefficient": float(
            candidate_model.named_steps["classifier"].coef_[0][
                len(candidate_model.named_steps["features"].transformer_list[0][1].named_steps["tfidf"].get_feature_names_out())
                + list(candidate_model.named_steps["features"].transformer_list[1][1].named_steps["vectorize"].get_feature_names_out()).index("path_length")
            ]
        ),
        "promotion_status": "NOT_PROMOTED",
    }, indent=2))


if __name__ == "__main__":
    run()