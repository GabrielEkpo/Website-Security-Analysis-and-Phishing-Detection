# Isolated URL Invariance Candidate Experiment

## Isolation and split

- Production fingerprint before/after: `c056ba034fb8f6f941ee3be5a3634e0b15e7235a73f63196003ed77bc9618c6c` / `c056ba034fb8f6f941ee3be5a3634e0b15e7235a73f63196003ed77bc9618c6c`.
- Source dataset SHA-256: `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`.
- Original rows: 235795; rows reserved out for the separate Nigerian check: 7; rows used for split: 235788.
- Split: GroupShuffleSplit, seed 42, held-out fraction 20%; exact-host groups, lowercased with terminal dot and leading www removed. Hostname groups are disjoint; this is not eTLD+1 grouping.
- Candidate training examples: 186956; held-out rows: 47931; training hosts: 175268; held-out hosts: 43818.
- Candidate-canonical duplicate handling: train excluded 2 rows with conflicting labels; held-out excluded 0 such rows. Same-label duplicates were collapsed only within their assigned partition.
- The held-out host list and evaluated held-out rows are frozen in `split_manifest.json` and `heldout_test_set.csv`.
- No Nigerian rows were added to either main partition. Any Nigerian host already present in PhiUSIIL was excluded from both partitions.

## Candidate changes

- Retains LogisticRegression and full-URL character TF-IDF (2–5 character n-grams, up to 12,000 features).
- Candidate-only canonicalization lowercases IDNA hostnames, removes a final hostname dot, collapses only an empty root path and `/`, and removes scheme-default ports (`https:443`, `http:80`). It preserves scheme, non-root paths, query, fragment, non-default ports, and `www`.
- Candidate structured branch applies `log1p` then `StandardScaler(with_mean=False)`; scaler and vectorizer are fitted only on training groups.
- No feature-selection, hyperparameter search, Nigerian augmentation, security-rule, threshold, or production changes were made.

## Main held-out metrics

| Metric              | Frozen production | Candidate |
| ------------------- | ----------------: | --------: |
| False-positive rate |          0.000074 |  0.000111 |
| Precision           |          0.999904 |  0.999856 |
| Recall              |          0.991544 |  0.993121 |
| F1                  |          0.995707 |  0.996477 |
| Brier score         |          0.003182 |  0.002930 |
| Log loss            |          0.016374 |  0.017190 |
| ROC AUC             |          0.999062 |  0.998575 |

Confusion matrices use label order `[0=legitimate, 1=phishing]`. Production: `[[26996, 2], [177, 20756]]`. Candidate: `[[26995, 3], [144, 20789]]`.

Calibration tables and full confusion counts are in `evaluation_report.json`.

## Formatting-pair consistency

Tested 2000 deterministic held-out host groups against uppercase, terminal-dot, root-slash, and explicit default-HTTPS-port forms. `www` was separately reported, not assumed equivalent.

- Production all-forms consistent within tolerance: `False`; max range `0.981886702928`.
- Candidate all-forms consistent within tolerance: `True`; max range `0`.

Per-variant pair counts and deltas, plus example hosts, are in `evaluation_report.json`.

## Separate Nigerian legitimate-domain check

- URLs: 31; raw label `1` for every row, mapped to legitimate. This set was not used for training, main evaluation, feature fitting, or tuning.
- Production correct legitimate classifications: 29/31.
- Candidate correct legitimate classifications: 29/31.
- This small all-legitimate set is a separate check, not evidence of generalization.

## Security regressions and disposition

- Existing Django tests: PASS (22 tests; Django system check reported no issues), run separately against the unchanged production configuration.
- The candidate was never placed at the production model path and is not integrated or deployed.
- Promotion status: NOT PROMOTED. The experiment is evidence for review only; production remains the baseline artifact.
- Hostname grouping does not fully prevent sibling-subdomain leakage because no Public Suffix List source was available locally.
