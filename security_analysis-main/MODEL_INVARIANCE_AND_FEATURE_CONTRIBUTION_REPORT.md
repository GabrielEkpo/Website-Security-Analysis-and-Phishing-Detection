# Model Invariance and Feature Contribution Report

## Scope and method

This is a read-only diagnostic of the existing production model. No application source, model artifact, dataset, thresholds, or security rules were modified. The Ecobank URL was deliberately excluded.

All scores below were computed locally from `artifacts/phishing_model.joblib` through the existing `PhishingAnalyzer`, `normalize_model_url`, feature extractors, fitted transformers, and classifier. No submitted URL was opened as a website. Artifact SHA-256 prefix: `c056ba034fb8`.

The production artifact returned class labels `[0, 1]`; class `1` is phishing. Probabilities in the tables are unrounded `predict_proba` values. The API rounds its `phishing_probability` field to four decimal places. Decision values are LogisticRegression's `decision_function` values before that rounding.

## 1. Reproduction

| Submitted URL             | Raw phishing probability | Raw model prediction | Final application prediction | Source                         | Risk score |
| ------------------------- | -----------------------: | -------------------- | ---------------------------- | ------------------------------ | ---------: |
| `https://example.com`     |               0.00717821 | legitimate           | legitimate                   | `ai_model`                     |       0.72 |
| `https://example.com/`    |               0.98770088 | phishing             | phishing                     | `ai_model`                     |      98.77 |
| `https://ug.nsuk.edu.ng`  |               0.01534163 | legitimate           | legitimate                   | `trusted_institutional_domain` |       1.53 |
| `https://ug.nsuk.edu.ng/` |               0.99406894 | phishing             | legitimate                   | `trusted_institutional_domain` |      99.41 |

For the NSUK slash case, the raw model prediction is phishing. The final trusted-host override changes only the final prediction and source; it does not replace the raw model probability or its contribution-derived risk score.

## 2. Fitted model and pipeline

The artifact is a scikit-learn `Pipeline` with steps `features` and `classifier`. The `features` step is a `FeatureUnion` in this order:

1. `url_characters`: `TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1, max_features=12000, norm="l2", use_idf=True, lowercase=True)`.
2. `url_properties`: `FunctionTransformer(extract_feature_dicts)` followed by `DictVectorizer`.

The final classifier is `LogisticRegression`. The FeatureUnion has no branch weights (`transformer_weights=None`). The structured branch has no scaler or other numeric transformation after `DictVectorizer`; the TF-IDF branch is L2-normalized, while structured values remain in their raw numeric scales.

The intercept is `+0.41391645`. The named structured-feature coefficients are:

| Feature                   | Fitted coefficient |
| ------------------------- | -----------------: |
| `url_length`              |        +0.52186335 |
| `host_length`             |        -0.38994930 |
| `path_length`             |        +8.65312971 |
| `dot_count`               |        +0.87677327 |
| `hyphen_count`            |        +0.61853600 |
| `at_count`                |        +0.00090349 |
| `question_count`          |        +0.01792175 |
| `equal_count`             |        -0.00408668 |
| `digit_ratio`             |        +6.96333265 |
| `subdomain_count`         |        +0.46085500 |
| `has_https`               |       -12.33337953 |
| `has_port`                |        +0.00000340 |
| `host_is_ip`              |        +0.00043256 |
| `uses_shortener`          |        +0.00092259 |
| `suspicious_word_count`   |        +2.00521000 |
| `encoded_character_count` |        -0.01099900 |

Values are printed to the shown precision, but calculations used the fitted floating-point coefficients. A structured feature's contribution is its transformed value multiplied by its corresponding named coefficient. The contribution calculation uses `DictVectorizer`'s fitted feature names rather than assuming dictionary insertion order matches classifier coefficient order.

## 3. Training versus inference representation

Training reads each URL, strips surrounding whitespace, calls `normalize_model_url`, then uses the fitted `FeatureUnion` and classifier. Inference validates/strips the submitted URL, calls the same `normalize_model_url`, and passes that string to the same saved pipeline. The structured transformer calls the same `extract_feature_dicts` and `extract_url_features` functions in both paths.

For the tested fully qualified HTTP(S) URLs, there is no evidence of a separate training-versus-inference feature extractor or an ordering mismatch. The same canonicalized string is passed through the saved pipeline. The variance occurs because `normalize_model_url` does not canonicalize several URL components and the model has learned highly sensitive weights for the resulting features.

The training script only deduplicates identical normalized strings. It does not group or deduplicate equivalence classes such as a URL with and without a root slash, so equivalent formatting variants can remain distinct training examples. The artifact does not retain the training rows or provenance needed to establish which examples caused each coefficient; this report does not infer that provenance.

## 4. Contribution arithmetic and reconstruction

For a transformed row, the fitted binary logistic decision is:

`z = intercept + character_TFIDF_dot_product + sum(structured_value * its_named_coefficient)`

The raw phishing probability is `sigmoid(z) = 1 / (1 + exp(-z))`, corresponding to class `1`. For every URL in the controlled matrix, the independently reconstructed `z` matched `classifier.decision_function` to floating-point precision (absolute residual below `1e-14`). Applying the sigmoid matched `predict_proba` (maximum observed discrepancy below `3e-17`).

The intercept is the constant `+0.41391645` for every URL. It is not a feature contribution and does not change between variants. It shifts every log-odds score by the same amount.

The branch-isolation counterfactuals in the next table are arithmetic diagnostics only, not additional model predictions: `char-only` changes the current URL's character contribution while holding the group's baseline structured contribution fixed; `structured-only` changes the structured contribution while holding the baseline character contribution fixed. The same intercept is included in both.

### Vector notation

For compactness, each `X` (structured values) and `C` (structured contributions) vector follows this exact order:

`url_length / host_length / path_length / dot_count / digit_ratio / subdomain_count / has_https / has_port / question_count / equal_count`

Other structured features for these cases (`hyphen_count`, `at_count`, `host_is_ip`, `uses_shortener`, `suspicious_word_count`, `encoded_character_count`) are all zero, so their values and contributions are zero. `char` is the character-branch dot product; `dChar` and `dStruct` are changes from that group's first row. `ngrams` gives nonzero TF-IDF features and count whose values differ from baseline. `top n-gram delta` lists the two largest absolute character-logit deltas by learned coefficient contribution; there are no changes for an identical normalized input.

## 5. Controlled invariance matrix: `example.com`

| Submitted URL                  | Model input; hostname; path                   | X                              | C                                                     | char; struct; dChar; dStruct               | ngrams; top n-gram delta             | z; raw phishing p       | char-only; structured-only p | Raw -> final; source; risk          |
| ------------------------------ | --------------------------------------------- | ------------------------------ | ----------------------------------------------------- | ------------------------------------------ | ------------------------------------ | ----------------------- | ---------------------------- | ----------------------------------- |
| `https://example.com`          | `https://example.com`; `example.com`; empty   | `19/11/0/1/0/0/1/0/0/0`        | `+9.915/-4.289/0/+0.877/0/0/-12.333/0/0/0`            | `+0.48723; -5.83065; 0; 0`                 | `63/0; unchanged`                    | `-4.92950; 0.00717821`  | `0.007178; 0.007178`         | legitimate -> legitimate; AI; 0.72  |
| `https://example.com/`         | `https://example.com/`; `example.com`; `/`    | `20/11/1/1/0/0/1/0/0/0`        | `+10.437/-4.289/+8.653/+0.877/0/0/-12.333/0/0/0`      | `+0.62759; +3.34435; +0.14036; +9.17499`   | `67/67; m/ +0.0371, .com/ +0.0371`   | `+4.38585; 0.98770088`  | `0.008251; 0.985874`         | phishing -> phishing; AI; 98.77     |
| `http://example.com`           | `http://example.com`; `example.com`; empty    | `18/11/0/1/0/0/0/0/0/0`        | `+9.394/-4.289/0/+0.877/0/0/0/0/0/0`                  | `+1.06966; +5.98087; +0.58243; +11.81152`  | `59/73; p:// +0.0730, tp:// +0.0730` | `+7.46445; 0.99942723`  | `0.012779; 0.998975`         | phishing -> phishing; AI; 99.94     |
| `https://EXAMPLE.COM`          | `https://example.com`; `example.com`; empty   | `19/11/0/1/0/0/1/0/0/0`        | `+9.915/-4.289/0/+0.877/0/0/-12.333/0/0/0`            | `+0.48723; -5.83065; 0; 0`                 | `63/0; identical to baseline`        | `-4.92950; 0.00717821`  | `0.007178; 0.007178`         | legitimate -> legitimate; AI; 0.72  |
| `https://example.com.`         | `https://example.com.`; `example.com.`; empty | `20/12/0/2/0/1/1/0/0/0`        | `+10.437/-4.679/0/+1.754/0/+0.461/-12.333/0/0/0`      | `+0.03814; -4.36110; -0.44909; +1.46954`   | `67/67; .com. -0.1616, m. -0.1065`   | `-3.90905; 0.01966506`  | `0.004593; 0.030473`         | legitimate -> legitimate; AI; 1.97  |
| `https://example.com?ref=test` | same; `example.com`; empty path               | `28/11/0/1/0/0/1/0/1/1`        | `+14.612/-4.289/0/+0.877/0/0/-12.333/0/+0.018/-0.004` | `+0.14828; -1.12004; -0.33895; +4.71061`   | `74/74; est -0.0770, st -0.0759`     | `-0.55784; 0.36404652`  | `0.005125; 0.445493`         | legitimate -> legitimate; AI; 36.40 |
| `https://example.com#section`  | same; `example.com`; empty path               | `27/11/0/1/0/0/1/0/0/0`        | `+14.090/-4.289/0/+0.877/0/0/-12.333/0/0/0`           | `-0.08710; -1.65574; -0.57433; +4.17491`   | `79/79; ti -0.1193, ion -0.0665`     | `-1.32892; 0.20933740`  | `0.004055; 0.319821`         | legitimate -> legitimate; AI; 20.93 |
| `https://example.com:443`      | same; `example.com`; empty path; port 443     | `23/11/0/1/0.130435/0/1/1/0/0` | `+12.003/-4.289/0/+0.877/+0.908/0/-12.333/~0/0/0`     | `+0.64093; -2.83493; +0.15370; +2.99572`   | `65/65; 43 +0.1308, 44 +0.0354`      | `-1.78008; 0.14429271`  | `0.008361; 0.126332`         | legitimate -> legitimate; AI; 14.43 |
| `https://example.com:8443`     | same; `example.com`; empty path; port 8443    | `24/11/0/1/0.166667/0/1/1/0/0` | `+12.525/-4.289/0/+0.877/+1.161/0/-12.333/~0/0/0`     | `+0.63731; -2.06077; +0.15008; +3.76988`   | `66/66; 43 +0.1291, 44 +0.0349`      | `-1.00954; 0.26706921`  | `0.008331; 0.238735`         | legitimate -> legitimate; AI; 26.71 |
| `https://www.example.com`      | `https://example.com`; `example.com`; empty   | `19/11/0/1/0/0/1/0/0/0`        | `+9.915/-4.289/0/+0.877/0/0/-12.333/0/0/0`            | `+0.48723; -5.83065; 0; 0`                 | `63/0; identical to baseline`        | `-4.92950; 0.00717821`  | `0.007178; 0.007178`         | legitimate -> legitimate; AI; 0.72  |
| `https://example.com/about`    | same; `example.com`; `/about`                 | `25/11/6/1/0/0/1/0/0/0`        | `+13.047/-4.289/+51.919/+0.877/0/0/-12.333/0/0/0`     | `+0.29016; +49.21931; -0.19707; +55.04996` | `80/80; out -0.0720, bout -0.0580`   | `+49.92339; 1.00000000` | `0.005902; 1.000000`         | phishing -> phishing; AI; 100       |

## 6. Controlled invariance matrix: `ug.nsuk.edu.ng`

| Submitted URL                     | Model input; hostname; path                       | X                              | C                                                          | char; struct; dChar; dStruct               | ngrams; top n-gram delta             | z; raw phishing p       | char-only; structured-only p | Raw -> final; source; risk                                      |
| --------------------------------- | ------------------------------------------------- | ------------------------------ | ---------------------------------------------------------- | ------------------------------------------ | ------------------------------------ | ----------------------- | ---------------------------- | --------------------------------------------------------------- |
| `https://ug.nsuk.edu.ng`          | same; `ug.nsuk.edu.ng`; empty                     | `22/14/0/3/0/2/1/0/0/0`        | `+11.481/-5.459/0/+2.630/0/+0.922/-12.333/0/0/0`           | `-1.81599; -2.75965; 0; 0`                 | `48/0; unchanged`                    | `-4.16172; 0.01534163`  | `0.015342; 0.015342`         | legitimate -> legitimate; trusted host; 1.53                    |
| `https://ug.nsuk.edu.ng/`         | same; `ug.nsuk.edu.ng`; `/`                       | `23/14/1/3/0/2/1/0/0/0`        | `+12.003/-5.459/+8.653/+2.630/0/+0.922/-12.333/0/0/0`      | `-1.70766; +6.41535; +0.10833; +9.17499`   | `50/50; .n +0.0180, .ed +0.0157`     | `+5.12160; 0.99406894`  | `0.017067; 0.993395`         | phishing -> legitimate; trusted host; 99.41                     |
| `http://ug.nsuk.edu.ng`           | same; `ug.nsuk.edu.ng`; empty                     | `21/14/0/3/0/2/0/0/0/0`        | `+10.959/-5.459/0/+2.630/0/+0.922/0/0/0/0`                 | `-1.09117; +9.05187; +0.72482; +11.81152`  | `44/58; p:// +0.0877, tp:// +0.0877` | `+8.37461; 0.99976940`  | `0.031162; 0.999524`         | phishing -> legitimate; trusted host; 99.98; `no_https` finding |
| `https://UG.NSUK.EDU.NG`          | `https://ug.nsuk.edu.ng`; `ug.nsuk.edu.ng`; empty | `22/14/0/3/0/2/1/0/0/0`        | `+11.481/-5.459/0/+2.630/0/+0.922/-12.333/0/0/0`           | `-1.81599; -2.75965; 0; 0`                 | `48/0; identical to baseline`        | `-4.16172; 0.01534163`  | `0.015342; 0.015342`         | legitimate -> legitimate; trusted host; 1.53                    |
| `https://ug.nsuk.edu.ng.`         | same; `ug.nsuk.edu.ng.`; empty                    | `23/15/0/4/0/3/1/0/0/0`        | `+12.003/-5.849/0/+3.507/0/+1.383/-12.333/0/0/0`           | `-1.70505; -1.29010; +0.11095; +1.46954`   | `49/49; ng. +0.0875, g. -0.0504`     | `-2.58124; 0.07035575`  | `0.017111; 0.063436`         | legitimate -> legitimate; trusted host; 7.04                    |
| `https://ug.nsuk.edu.ng?ref=test` | same; `ug.nsuk.edu.ng`; empty path                | `31/14/0/3/0/2/1/0/1/1`        | `+16.178/-5.459/0/+2.630/0/+0.922/-12.333/0/+0.018/-0.004` | `-1.87723; +1.95096; -0.06123; +4.71061`   | `59/59; est -0.0889, st -0.0876`     | `+0.48765; 0.61955224`  | `0.014444; 0.633876`         | phishing -> legitimate; trusted host; 61.96                     |
| `https://ug.nsuk.edu.ng#section`  | same; `ug.nsuk.edu.ng`; empty path                | `30/14/0/3/0/2/1/0/0/0`        | `+15.656/-5.459/0/+2.630/0/+0.922/-12.333/0/0/0`           | `-2.08233; +1.41526; -0.26634; +4.17491`   | `64/64; ti -0.1368, ion -0.0762`     | `-0.25316; 0.43704665`  | `0.011797; 0.503295`         | legitimate -> legitimate; trusted host; 43.70                   |
| `https://ug.nsuk.edu.ng:443`      | same; `ug.nsuk.edu.ng`; empty path; port 443      | `26/14/0/3/0.115385/2/1/1/0/0` | `+13.568/-5.459/0/+2.630/+0.803/+0.922/-12.333/~0/0/0`     | `-1.55017; +0.13127; +0.26582; +2.89092`   | `50/50; 43 +0.1564, 44 +0.0423`      | `-1.00498; 0.26796276`  | `0.019920; 0.219119`         | legitimate -> legitimate; trusted host; 26.80                   |
| `https://ug.nsuk.edu.ng:8443`     | same; `ug.nsuk.edu.ng`; empty path; port 8443     | `27/14/0/3/0.148148/2/1/1/0/0` | `+14.090/-5.459/0/+2.630/+1.032/+0.922/-12.333/~0/0/0`     | `-1.51442; +0.88128; +0.30157; +3.64092`   | `51/51; 43 +0.1534, 44 +0.0415`      | `-0.21922; 0.44541223`  | `0.020630; 0.372665`         | legitimate -> legitimate; trusted host; 44.54                   |
| `https://www.ug.nsuk.edu.ng`      | `https://ug.nsuk.edu.ng`; `ug.nsuk.edu.ng`; empty | `22/14/0/3/0/2/1/0/0/0`        | `+11.481/-5.459/0/+2.630/0/+0.922/-12.333/0/0/0`           | `-1.81599; -2.75965; 0; 0`                 | `48/0; identical to model baseline`  | `-4.16172; 0.01534163`  | `0.015342; 0.015342`         | legitimate -> legitimate; AI; 1.53                              |
| `https://ug.nsuk.edu.ng/about`    | same; `ug.nsuk.edu.ng`; `/about`                  | `28/14/6/3/0/2/1/0/0/0`        | `+14.612/-5.459/+51.919/+2.630/0/+0.922/-12.333/0/0/0`     | `-1.76811; +52.29031; +0.04788; +55.04996` | `60/60; out -0.0843, bout -0.0679`   | `+50.93611; 1.00000000` | `0.016082; 1.000000`         | phishing -> legitimate; trusted host; 100                       |

The unrounded `has_port` contributions are nonzero but negligible (coefficient approximately `+3.4e-6`); they display as `~0` above. All other listed contributions were computed from the exact fitted coefficient. `Decision reconstruction error` is below `1e-14` for every row.

## 7. Canonicalization findings

`normalize_model_url` lowercases the parsed hostname and strips a leading `www.` from the hostname before rebuilding the netloc. It does not remove a trailing root dot, collapse an empty path and `/`, remove default port 443, or discard a query or fragment.

| Variation               | Model representation result                                                                      | Interpretation and observed effect                                                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hostname case           | Canonicalized to lowercase; exact same model string/features in these tests                      | Expected canonical equivalence confirmed.                                                                                                                                                   |
| Leading `www.`          | Removed for model input; example and apex inputs score identically                               | Model treats them as equivalent. The application trust rule does not remove `www.`, so final source can differ for NSUK. DNS/application equivalence is not established by this model test. |
| Trailing DNS root dot   | Retained in model input                                                                          | Host fields and character n-grams change; probability changes. The NSUK trusted-host checker separately strips the trailing dot.                                                            |
| Optional root slash     | Retained as path `/`; not equivalent to empty path                                               | One path character contributes `+8.65313` structurally, plus a small URL-length and TF-IDF change. This alone flips both raw predictions.                                                   |
| Explicit HTTPS port 443 | Retained; `has_port=1`, digits and full URL text differ                                          | Same conventional HTTPS endpoint candidate, but model representation and probability differ. No port equivalence is applied.                                                                |
| HTTP vs HTTPS           | Scheme retained and `has_https` differs                                                          | Meaningful security difference; model probability rises substantially for HTTP in this artifact.                                                                                            |
| Different path          | Retained and counted by `path_length`, URL length, and character n-grams                         | Meaningful resource difference, but the learned path coefficient is so large that even `/about` saturates the probability.                                                                  |
| Query string            | Retained and included in full-string TF-IDF and some structured counts                           | Can be semantically meaningful; here it creates material probability changes. It is not canonicalized away.                                                                                 |
| Fragment                | Retained in the model string and TF-IDF; excluded from `parsed.path` and most structured parsing | Fragments generally are not sent in the HTTP request, but can affect client-side routing. Model still treats the text as predictive and changes its score.                                  |
| Non-default port 8443   | Retained; port flag and digits included                                                          | Distinct network endpoint and meaningfully different destination candidate; score changes, though less than path variants here.                                                             |

The model has no domain-only canonical identity representation: the TF-IDF vectorizer receives the complete normalized URL string, including scheme, path, query, fragment, and port. The structured extractor also uses the entire string for `url_length`, dot count, punctuation counts, and digit ratio.

## 8. Feature branch isolation and confirmed cause

The exact contribution comparisons establish both branch effects, but they also establish that the structured branch is dominant for the extreme slash/path flips:

| Comparison                            | Change in character contribution | Change in structured contribution | Actual probability change | Probability with only character branch changed | Probability with only structured branch changed |
| ------------------------------------- | -------------------------------: | --------------------------------: | ------------------------- | ---------------------------------------------: | ----------------------------------------------: |
| Example root URL -> root slash        |                         +0.14036 |                          +9.17499 | 0.007178 -> 0.987701      |                                       0.008251 |                                        0.985874 |
| Example root URL -> `/about`          |                         -0.19707 |                         +55.04996 | 0.007178 -> 1.000000      |                                       0.005902 |                                        1.000000 |
| NSUK root URL -> root slash           |                         +0.10833 |                          +9.17499 | 0.015342 -> 0.994069      |                                       0.017067 |                                        0.993395 |
| NSUK root URL -> `/about`             |                         +0.04788 |                         +55.04996 | 0.015342 -> 1.000000      |                                       0.016082 |                                        1.000000 |
| Example root URL -> query `?ref=test` |                         -0.33895 |                          +4.71061 | 0.007178 -> 0.364047      |                                       0.005125 |                                        0.445493 |
| NSUK root URL -> query `?ref=test`    |                         -0.06123 |                          +4.71061 | 0.015342 -> 0.619552      |                                       0.014444 |                                        0.633876 |

The branch-isolation values are calculated by adding one branch's actual contribution to the other branch's baseline contribution and applying the same intercept and sigmoid. They are diagnostic counterfactuals; they do not represent retrained models.

**Confirmed cause:** incomplete URL canonicalization exposes harmless syntactic variation to both fitted feature branches, and the unscaled numeric structured features have extreme learned sensitivity—particularly `path_length`. Character TF-IDF also changes, but contributes comparatively little to the root-slash and `/about` decision jumps. Query, fragment, trailing-dot, and port changes can receive material contributions from both branches. The issue is not a different training versus inference transformer, nor frontend/API disagreement.

The `path_length` value is not mathematically a `path_length * coefficient` after a scaling transformation: no scaler is fitted in that branch. A one-character path contributes `+8.65313`; six path characters contribute `+51.91878`. A URL length increase from 19 to 20 adds a further `+0.52186`. The classifier therefore saturates near probability 1 for modest nonempty paths.

For HTTP, losing the `has_https` contribution removes `-12.33338`, which is a large increase to the phishing logit; the HTTP character n-grams and URL length also differ. This is a meaningful scheme/security change, unlike case changes. Default port 443 contributes almost nothing through `has_port` itself, but the digits, URL length, digit ratio, and character n-grams change the score.

## 9. Remaining uncertainties

- The saved model does not include its original training examples, so this inspection cannot identify which records produced the large path coefficient or quantify formatting variants in training.
- The code uses a random stratified row split, not a grouping split by canonical hostname or URL-equivalence class. The training report may therefore overstate generalization across related variants; this audit did not recompute training metrics.
- The model-only `www.` normalization assumes `www.` can be removed for prediction. This is implemented consistently but is not universally guaranteed to be DNS/application-equivalent for every host.
- Fragments are not sent as part of the HTTP request, but client applications may use them for routing; whether to strip them depends on the system's intended semantics.
- The trusted NSUK rule deliberately overrides final prediction while retaining model probability/risk. This is separate from the model feature instability and is not changed or evaluated as a security-policy question here.
- The report describes this artifact version (`c056ba034fb8`). Results should be rechecked if the deployed artifact changes.

## 10. Recommended correction strategy

Do not patch the production model or promote a retrained artifact based solely on these probes. Before implementation, agree on the input equivalence contract. A conservative candidate approach is:

1. Define canonicalization rules separately for host identity and model URL features. Consider lowercasing and IDNA-normalizing hostnames, deciding explicitly whether a final dot, leading `www.`, empty path/root slash, and explicit default port are canonical equivalents, and preserving meaningful scheme, path, query, fragment, and non-default-port distinctions where the detection objective requires them.
2. Make training and inference consume the same canonical representation and feature extractor. Deduplicate or group training examples by that representation, and use grouped validation so equivalent URLs cannot leak across train and held-out partitions.
3. Reassess structured feature scales and coefficient behavior. In particular, do not allow raw path length to contribute more than eight logit units per character without a validated domain rationale. Any feature scaling, clipping, feature redesign, or model change requires a separately trained candidate and held-out validation; do not modify the production artifact during this diagnostic.
4. Compare baseline and candidate on untouched hold-out URLs, formatting-equivalence pairs, relevant non-equivalent URL pairs, and existing security-rule regressions. Report calibration and false-positive rates in addition to aggregate classification metrics.
5. Keep raw model probability, final rule/trusted classification, findings score, and combined risk explicitly distinct in reporting and UI. A trusted override must not be interpreted as evidence that the underlying model scored the URL as safe.

These are recommendations only. No correction was implemented or model retrained.

## 11. Regression tests required before implementation

At minimum, add tests that exercise the real fitted preprocessing/model contract and then run the existing security-rule suite:

- Assert exact normalized representations for case variants and each chosen canonical form.
- Assert the agreed probability invariance tolerance for canonical-equivalent pairs: case variants, optional root slash if declared equivalent, trailing dot if declared equivalent, and explicit default HTTPS port if declared equivalent.
- Assert `www.` equivalence only if that equivalence is explicitly part of the product contract; include a trusted-institutional-host case to distinguish raw model normalization from final application source.
- Assert that HTTP/HTTPS, distinct paths, queries, fragments, and non-default ports remain distinct when the product contract says they are meaningful; avoid asserting they must have identical probabilities.
- Reconstruct each fitted LogisticRegression decision score from the transformed character and structured feature branches, verify `sigmoid(decision_function)` against class-1 `predict_proba`, and verify positive-class indexing from `classes_`.
- Include a regression for the current root-slash and `/about` failures so their intended behavior is explicit.
- Validate with grouped hold-out data by hostname/equivalence class and check false-positive and calibration changes before any candidate is promoted.
- Retain regression coverage for known-phishing detection, brand lookalikes, exact NSUK trust, NSUK lookalikes, and the preserved raw model probability under final rule overrides.

## Verification record

- Production artifact loaded without writing to it; fingerprint confirmed as `c056ba034fb8`.
- All controlled inputs were processed locally by existing parser, feature functions, and fitted model. No URL was opened externally.
- Decision-score reconstruction matched `decision_function` to less than `1e-14`; sigmoid probability matched `predict_proba` to less than `3e-17` for the tested rows.
- Existing Django tests passed: 22 tests, `OK`; system check reported no issues.
- A fresh SHA-256 check confirmed the production model artifact still begins with `c056ba034fb8`.
- No application files, datasets, model artifacts, security rules, or thresholds were modified. This report is the only requested workspace artifact.
