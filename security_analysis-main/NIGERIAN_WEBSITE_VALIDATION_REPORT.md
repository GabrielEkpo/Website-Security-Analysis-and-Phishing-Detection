# Nigerian Website Validation Report

- Total URLs tested: 31
- Correctly classified URLs: 29
- Incorrectly classified URLs: 2
- URLs that could not be reached or tested: 0

## Validation Results

| # | URL | Expected | Prediction | Phishing Probability | Risk Score | Result |
|---:|---|---|---|---:|---:|---|
| 1 | <https://www.nigeria.gov.ng> | legitimate | legitimate | 0.0018 | 0.18 | PASS |
| 2 | <https://www.nigerianstat.gov.ng> | legitimate | legitimate | 0.0054 | 0.54 | PASS |
| 3 | <https://www.cbn.gov.ng> | legitimate | legitimate | 0.002 | 0.2 | PASS |
| 4 | <https://www.firs.gov.ng> | legitimate | legitimate | 0.0023 | 0.23 | PASS |
| 5 | <https://www.immigration.gov.ng> | legitimate | legitimate | 0.0024 | 0.24 | PASS |
| 6 | <https://www.sec.gov.ng> | legitimate | legitimate | 0.0016 | 0.16 | PASS |
| 7 | <https://www.nationalassembly.gov.ng> | legitimate | legitimate | 0.0089 | 0.89 | PASS |
| 8 | <https://www.npf.gov.ng> | legitimate | legitimate | 0.0013 | 0.13 | PASS |
| 9 | <https://www.unilag.edu.ng> | legitimate | legitimate | 0.0033 | 0.33 | PASS |
| 10 | <https://www.ui.edu.ng> | legitimate | legitimate | 0.0036 | 0.36 | PASS |
| 11 | <https://www.abu.edu.ng> | legitimate | legitimate | 0.0037 | 0.37 | PASS |
| 12 | <https://www.unilorin.edu.ng> | legitimate | legitimate | 0.0044 | 0.44 | PASS |
| 13 | <https://www.unn.edu.ng> | legitimate | legitimate | 0.0031 | 0.31 | PASS |
| 14 | <https://www.funaab.edu.ng> | legitimate | legitimate | 0.0052 | 0.52 | PASS |
| 15 | <https://www.nau.edu.ng> | legitimate | legitimate | 0.0041 | 0.41 | PASS |
| 16 | <https://www.yabatech.edu.ng> | legitimate | legitimate | 0.0126 | 1.26 | PASS |
| 17 | <https://www.federalpolyilaro.edu.ng> | legitimate | legitimate | 0.0063 | 0.63 | PASS |
| 18 | <https://www.polyibadan.edu.ng> | legitimate | legitimate | 0.0091 | 0.91 | PASS |
| 19 | <https://www.kwasu.edu.ng> | legitimate | legitimate | 0.0033 | 0.33 | PASS |
| 20 | <https://www.fceogieru.edu.ng> | legitimate | legitimate | 0.0069 | 0.69 | PASS |
| 21 | <https://www.fceyola.edu.ng> | legitimate | legitimate | 0.0029 | 0.29 | PASS |
| 22 | <https://www.fedpolyado.edu.ng> | legitimate | legitimate | 0.0055 | 0.55 | PASS |
| 23 | <https://www.gtbank.com> | legitimate | legitimate | 0.0076 | 0.76 | PASS |
| 24 | <https://www.firstbanknigeria.com> | legitimate | legitimate | 0.0154 | 1.54 | PASS |
| 25 | <https://www.accessbankplc.com> | legitimate | legitimate | 0.071 | 7.1 | PASS |
| 26 | <https://www.zenithbank.com> | legitimate | legitimate | 0.01 | 1.0 | PASS |
| 27 | <https://www.ubagroup.com> | legitimate | legitimate | 0.0099 | 0.99 | PASS |
| 28 | <https://www.stanbicibtc.com> | legitimate | legitimate | 0.0113 | 1.13 | PASS |
| 29 | <https://www.unionbankng.com> | legitimate | legitimate | 0.0158 | 1.58 | PASS |
| 30 | <https://www.ecobank.com/ng> | legitimate | phishing | 1.0 | 100.0 | FAIL |
| 31 | <https://ug.nsuk.edu.ng/> | legitimate | phishing | 0.9941 | 99.41 | FAIL |

## Special Result: NSUK Undergraduate Portal

- URL: https://ug.nsuk.edu.ng/
- Expected classification: legitimate (label 0)
- API prediction: phishing
- Phishing probability: 0.9941
- Risk score: 99.41
- Result: FAIL

## Unreachable or Failed URLs
None.

## Overall Observations
- The project API accepted and processed each dataset URL through the normal CSRF-protected POST flow.
- The dataset is composed entirely of legitimate URLs, so a correct model response should classify each as legitimate.
- The validation was performed using the current application and model artifact without retraining or modifying the codebase.
- No dataset entries were changed as part of this validation task.
