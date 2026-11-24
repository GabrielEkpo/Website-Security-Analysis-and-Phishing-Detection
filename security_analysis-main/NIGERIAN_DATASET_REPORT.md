# Nigerian Supplementary Legitimate Websites Dataset Report

## 1. Scope and constraints

This report documents a supplementary legitimate-only Nigerian website dataset created without altering the original PhiUSIIL dataset, the saved model artifact, or the existing application behavior.

The goal was to add a clean, verified set of legitimate Nigerian domains for future analysis work while keeping the current project structure and runtime behavior untouched.

## 2. Data format and compatibility

The dataset was created in the project folder:

- `security_analysis-main/dataset/nigerian_websites_dataset.csv`

The file uses the project-compatible structure:

- `URL`
- `Label`
- `Institution`
- `Category`
- `Source`

The label mapping follows the existing training pipeline:

- `1` = legitimate
- This matches the project logic in `security_analysis-main/scripts/train_model.py`, which interprets `1` as the legitimate class when the Phishing label is configured as `0`.

## 3. Collection approach

The dataset contains genuine, established Nigerian institutional websites, primarily from:

- federal and state government agencies
- universities and polytechnics
- colleges of education
- banks and financial institutions
- major public-service and official institutional portals

The selection prioritized official institutional homepages and recognized public-sector websites. Each domain was checked against the known institutional naming and official portal conventions, and no suspicious lookalike or unverified domains were included.

## 4. Verification and quality checks

### URL validation

The following checks were applied:

- only official institutional websites were included
- HTTPS URLs were preferred where available
- duplicates were removed
- no fabricated or speculative domains were added
- no lookalike or impersonation patterns were included

### Validation results

A read-only validation of the final dataset returned:

- total websites: 30
- duplicate URLs: 0
- missing values: 0
- all source fields present: True
- all labels legitimate (`1`): True

## 5. Category breakdown

The final category counts are:

- government: 8
- university: 8
- polytechnic: 4
- college_of_education: 2
- financial: 8

This gives a balanced set of verified Nigerian institutional domains across public-sector, academic, and financial categories.

## 6. Example entries included

The dataset includes official institutions such as:

- Nigeria Federal Government portal
- National Bureau of Statistics
- Central Bank of Nigeria
- Federal Inland Revenue Service
- Securities and Exchange Commission
- University of Lagos
- University of Ibadan
- Ahmadu Bello University
- University of Ilorin
- University of Nigeria, Nsukka
- Yaba College of Technology
- Federal Polytechnic Ilaro
- Federal College of Education Okene
- Guaranty Trust Bank
- First Bank of Nigeria
- Access Bank
- Zenith Bank
- UBA Group
- Stanbic IBTC Bank

## 7. Exclusions and notes

No entries were excluded during the final validation because all rows were complete, unique, and properly sourced.

The dataset intentionally contains only legitimate websites and does not include any phishing-like or suspicious domains.

## 8. Status of the existing project

The following were intentionally not changed:

- original PhiUSIIL dataset
- training script
- saved model artifact
- frontend application
- backend application
- runtime behavior

No retraining was performed, and no existing application functionality was modified.

## 9. Files created

- `security_analysis-main/dataset/nigerian_websites_dataset.csv`
- `security_analysis-main/NIGERIAN_DATASET_REPORT.md`

## 10. Final confirmation

The supplementary Nigerian legitimate dataset has been created and validated successfully. The existing application and trained model remain untouched, as required.
