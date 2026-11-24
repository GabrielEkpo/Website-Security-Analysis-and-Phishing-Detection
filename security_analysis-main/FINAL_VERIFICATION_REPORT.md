# Final Verification Report

## Scope

This report is based only on the existing dataset, training script, backend implementation, frontend code, and saved model artifact already present in the project. No retraining, model replacement, dataset modification, or application code edits were performed.

## 1) Domain-level data leakage verification

### Evidence inspected

- training script: `security_analysis-main/scripts/train_model.py`
- dataset: `phiusiil+phishing+url+dataset/PhiUSIIL_Phishing_URL_Dataset.csv`

The training script removes duplicate URLs only:

```python
seen_urls: dict[str, int] = {}
for row_number, row in enumerate(reader, start=2):
    url = normalize_model_url((row.get(url_column) or "").strip())
    raw_label = (row.get(label_column) or "").strip()
    ...
    if url in seen_urls:
        if seen_urls[url] != label:
            raise ValueError(f"URL has conflicting labels on row {row_number}")
        duplicate_count += 1
        continue
    seen_urls[url] = label
    urls.append(url)
    labels.append(label)
```

The split is performed as:

```python
train_test_split(
    urls,
    labels,
    test_size=0.2,
    random_state=42,
    stratify=labels,
)
```

This guarantees URL-level de-duplication, but it does not guarantee registered-domain separation.

### Result from read-only dataset analysis

Using the actual CSV and the same split logic already used by the training script, a read-only analysis found:

- Unique URLs: 235,212
- Train URLs: 188,169
- Test URLs: 47,043
- Unique registered domains: 172,701
- Overlapping registered domains between train and test: 2,907

This means the same registered domain can appear in both training and test sets, even after duplicate-URL removal.

### Why this matters

Domain overlap can inflate reported evaluation metrics because many URLs from the same domain share lexical patterns, hosting characteristics, and URL structure. A model may appear stronger than it really is if it sees similar domain behavior in both train and test folds.

This does not mean the evaluation is invalid, but it means the reported metrics are optimistic relative to a strict domain-disjoint evaluation. The current assessment is still useful for a baseline, but it is not a clean domain-generalization test.

## 2) Risk-score and classification consistency

### Backend formula inspected

The backend logic in `security_analysis-main/phishing_detector/analyzer.py` is:

```python
probabilities = self.model.predict_proba([normalize_model_url(url)])[0]
classes = list(self.model.classes_)
phishing_probability = float(probabilities[classes.index(1)])
probability = phishing_probability
findings = self._website_findings(url, page_html)
rule_score = min(sum({"low": 10, "medium": 20, "high": 35}[f.severity] for f in findings), 100)
risk_score = round(max(probability * 100, rule_score), 2)
prediction = "phishing" if probability >= 0.5 else "legitimate"
```

The returned payload is:

```python
return {
    "url": url,
    "prediction": prediction,
    "label": prediction,
    "phishing_probability": round(probability, 4),
    "risk_score": risk_score,
    "findings_risk_score": rule_score,
    ...
}
```

### Interpretation

- `phishing_probability` is the model’s estimated probability of the phishing class, in the range 0 to 1.
- `prediction` is a thresholded label:
  - `"phishing"` if `phishing_probability >= 0.5`
  - `"legitimate"` otherwise
- `findings_risk_score` is the sum of heuristic finding severities only.
- `risk_score` is the larger of:
  - `phishing_probability * 100`
  - `findings_risk_score`

This makes the risk score a blended value that can rise due to rule-based findings even when the model still predicts a legitimate URL.

### Can heuristic findings increase risk without changing prediction?

Yes. The formula `max(probability * 100, rule_score)` makes this possible.

Example logic:

- model probability = 0.009 (0.9%)
- findings risk = 35
- result: prediction = `"legitimate"`, risk_score = `35.0`

That behavior matches the actual implementation.

### Frontend presentation checked

The frontend in `phishing detection website/script.js` does:

```javascript
const probability = Math.max(
  0,
  Math.min(1, Number(result.phishing_probability)),
);
const riskScore = Math.max(0, Math.min(100, Number(result.risk_score)));
const findingsRiskScore = Math.max(
  0,
  Math.min(100, Number(result.findings_risk_score)),
);

const riskClass = getRiskClassFromRiskScore(riskScore);
const prediction = result.prediction === "phishing" ? "phishing" : "legitimate";

riskLevel.textContent =
  riskClass === "danger"
    ? "HIGH RISK"
    : riskClass === "warning"
      ? "CAUTION"
      : "LOW RISK";
document.getElementById("riskPercentage").textContent = Math.round(riskScore);
document.getElementById("riskMessage").textContent =
  prediction === "phishing"
    ? `The model predicts phishing (${(probability * 100).toFixed(1)}% probability). Do not enter sensitive information.`
    : `The model predicts a legitimate URL (${(probability * 100).toFixed(1)}% phishing probability). Review the findings before proceeding.`;
```

### Inconsistency or misleading presentation

There is a meaningful semantic mismatch between the displayed risk label and the model prediction label:

- `prediction` is a thresholded class decision based on phishing probability.
- `risk_score` is a severity score that can move independently because of heuristics.
- The UI uses the risk score to decide the badge (`LOW RISK`, `CAUTION`, `HIGH RISK`), even when the message still says the model predicts a legitimate URL.

This is not a software crash or logic bug, but it can confuse users into treating the UI risk band as equivalent to the model label. In other words:

- a URL can be `prediction = "legitimate"` and still show `CAUTION` or `HIGH RISK` if rule-based findings push the risk score upward.
- the frontend currently blends both concepts in one display without a clear distinction.

This is consistent with the backend implementation, but it is potentially misleading for end users.

## 3) Summary of findings

1. Domain leakage risk exists at the registered-domain level because the training script removes duplicate URLs but does not enforce domain-level separation.
2. A read-only analysis of the existing dataset and split found 2,907 overlapping registered domains between train and test.
3. This means the published evaluation metrics are likely optimistic and may overestimate generalization to unseen domains.
4. The backend scoring logic is internally consistent: `prediction` is based on the phishing probability threshold, while `risk_score` is the maximum of model probability risk and rule-based findings risk.
5. Heuristic findings can indeed increase `risk_score` without changing `prediction`.
6. The frontend displays this blended score as the primary risk band, which can be misleading when the model still calls a URL legitimate but the rule-based score is elevated.

No retraining or model replacement was performed.
