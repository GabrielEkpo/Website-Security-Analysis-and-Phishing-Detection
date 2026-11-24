from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import FunctionTransformer

from phishing_detector.features import extract_feature_dicts, normalize_model_url


def _phishing_label(value: str, numeric_phishing_label: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"phishing", "malicious"}:
        return 1
    if normalized in {"legitimate", "benign"}:
        return 0
    if normalized in {"0", "1"}:
        return int(normalized == numeric_phishing_label)
    raise ValueError("Labels must be 0/1, legitimate/phishing, or benign/malicious")


def train(input_csv: Path, output_model: Path, numeric_phishing_label: str = "0") -> None:
    urls: list[str] = []
    labels: list[int] = []
    duplicate_count = 0
    with input_csv.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        columns = {name.strip().lower(): name for name in (reader.fieldnames or [])}
        url_column = columns.get("url")
        label_column = columns.get("label")
        if url_column is None or label_column is None:
            raise ValueError("Training CSV must contain URL and label columns")
        seen_urls: dict[str, int] = {}
        for row_number, row in enumerate(reader, start=2):
            url = normalize_model_url((row.get(url_column) or "").strip())
            raw_label = (row.get(label_column) or "").strip()
            if not url or not raw_label:
                raise ValueError(f"Row {row_number} needs both a URL and a label")
            label = _phishing_label(raw_label, numeric_phishing_label)
            if url in seen_urls:
                if seen_urls[url] != label:
                    raise ValueError(f"URL has conflicting labels on row {row_number}")
                duplicate_count += 1
                continue
            seen_urls[url] = label
            urls.append(url)
            labels.append(label)
    if len(set(labels)) != 2 or len(urls) < 10:
        raise ValueError("Provide at least 10 rows containing both classes")

    train_urls, test_urls, train_labels, test_labels = train_test_split(
        urls,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )
    features = FeatureUnion(
        [
            ("url_characters", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1, max_features=12000)),
            ("url_properties", Pipeline([
                ("extract", FunctionTransformer(extract_feature_dicts, validate=False)),
                ("vectorize", DictVectorizer()),
            ])),
        ]
    )
    model = Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(solver="liblinear", max_iter=200, random_state=42)),
    ])
    model.fit(train_urls, train_labels)
    predictions = model.predict(test_urls)
    precision, recall, f1_score, _ = precision_recall_fscore_support(
        test_labels, predictions, average="binary", zero_division=0
    )
    output_model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_model)
    print(f"Unique URLs: {len(urls)} (removed {duplicate_count} duplicates)")
    print(f"Train/test rows: {len(train_urls)}/{len(test_urls)}")
    print("Positive class: phishing")
    print(f"Accuracy: {accuracy_score(test_labels, predictions):.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1_score:.4f}")
    print("Confusion matrix (rows=true, columns=predicted; labels=[legitimate, phishing]):")
    print(confusion_matrix(test_labels, predictions, labels=[0, 1]))
    print(f"Saved model to {output_model}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the phishing URL classifier.")
    parser.add_argument("--input", type=Path, required=True, help="CSV with url,label columns")
    parser.add_argument("--output", type=Path, default=Path("artifacts/phishing_model.joblib"))
    parser.add_argument(
        "--phishing-label",
        choices=("0", "1"),
        default="0",
        help="Numeric label representing phishing (PhiUSIIL uses 0)",
    )
    args = parser.parse_args()
    train(args.input, args.output, args.phishing_label)
