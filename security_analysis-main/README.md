# Website Security Analysis and Phishing Detection

This project implements an AI-assisted website security analysis dashboard and phishing detector for educational and research use. The system combines a trained scikit-learn classifier with rule-based security findings for URL review, phishing assessment, and safe/unsafe classification.

## Project purpose

The application is designed to review submitted URLs and text content for indicators associated with phishing and suspicious web behavior. It evaluates:

- URL structure and domain characteristics
- Known phishing hostnames
- Brand impersonation and lookalike patterns
- Missing or insecure transport protocols
- Suspicious form and HTML indicators
- Model-based phishing probability from the trained classifier

The system intentionally preserves the distinction between:

- model-based classification
- security-rule detections
- trusted institutional exceptions
- risk scoring
- final user-facing assessment

## Architecture

The project contains a small Django backend and a front-end dashboard:

- Django application: `security_analysis-main/`
- Static UI assets: `phishing detection website/`
- Original phishing dataset: `phiusiil+phishing+url+dataset/`

The backend exposes JSON endpoints for analysis and known-phishing list retrieval. The front-end consumes those responses and presents the assessment in a clear dashboard layout.

## Technologies used

- Python
- Django
- scikit-learn
- joblib
- HTML, CSS, and JavaScript

## Installation

```powershell
python -m pip install -r requirements.txt
```

## Run the Django application

From the project directory:

```powershell
python manage.py runserver
```

Then open:

```text
http://127.0.0.1:8000/
```

The front-end posts JSON to the same-origin endpoint:

```text
POST /api/analyze/
```

Example payload:

```json
{ "url": "https://example.com" }
```

The optional `html` field may be included for passive HTML-based findings, but the server does not fetch remote content itself.

## Model training

The original dataset is not replaced or modified. The training process uses the PhiUSIIL dataset and preserves the project’s label convention:

- `1` = legitimate
- `0` = phishing

Training command:

```powershell
python -m scripts.train_model --input ..\phiusiil+phishing+url+dataset\PhiUSIIL_Phishing_URL_Dataset.csv --output artifacts\phishing_model.joblib
```

The project intentionally keeps the production model artifact separate from candidate validation experiments. Candidate-model work must be evaluated before any production change.

## Security rules and model behavior

The application includes both ML-based predictions and rule-based checks:

- known phishing hostname detection
- NSUK trusted-domain handling
- NSUK lookalike detection
- high-severity brand lookalike findings
- security findings from HTML and URL analysis

These checks do not replace the model and should not be treated as proof of malicious intent on their own. Final classification is a combination of model output, security findings, and trusted-domain logic.

## Tests

Run the automated checks with:

```powershell
python manage.py test tests
```

## Important limitations

- This is not a production-grade internet security boundary.
- The model should be evaluated carefully before being used as a deployment-critical control.
- Any candidate model must demonstrate generalization to previously unseen URLs before being promoted.
- Production model and dataset files are intentionally preserved during candidate-model investigation.

## Project documentation

Additional project-specific documentation files are included in the repository and should be treated as supporting material rather than replacement for this README.
