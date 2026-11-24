from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
import csv
import json

import joblib
from django.test import Client, SimpleTestCase, override_settings
from sklearn.dummy import DummyClassifier

from django_integration.views import get_analyzer
from phishing_detector.analyzer import KNOWN_PHISHING_DOMAINS, PhishingAnalyzer
from phishing_detector.features import extract_url_features, normalize_model_url

PROJECT_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_DIR / "artifacts" / "phishing_model.joblib"


class DetectorTests(TestCase):
    def test_features_capture_risky_url_properties(self):
        features = extract_url_features("http://192.168.1.1/login/verify?password=1")
        self.assertEqual(features["host_is_ip"], 1.0)
        self.assertEqual(features["has_https"], 0.0)
        self.assertGreaterEqual(features["suspicious_word_count"], 2)

    def test_analyzer_returns_findings(self):
        model = DummyClassifier(strategy="prior")
        model.fit(["https://example.com", "http://192.168.1.1/login"], [0, 1])
        with TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.joblib"
            joblib.dump(model, model_path)
            result = PhishingAnalyzer(model_path).analyze(
                "http://192.168.1.1/login",
                "<form action='https://other.example/collect'><input type='password'></form>",
            )
            codes = {finding["code"] for finding in result["findings"]}
            self.assertIn("ip_host", codes)
            self.assertIn("password_over_http", codes)
            self.assertIn("external_form_target", codes)
            self.assertEqual(result["ai_model"]["type"], "DummyClassifier")


@override_settings(PHISHING_MODEL_PATH=MODEL_PATH)
class AnalyzeEndpointTests(SimpleTestCase):
    def setUp(self):
        get_analyzer.cache_clear()
        self.client = Client(enforce_csrf_checks=True)
        self.client.get("/")
        self.csrf_token = self.client.cookies["csrftoken"].value

    def tearDown(self):
        get_analyzer.cache_clear()

    def post_json(self, payload):
        return self.client.post(
            "/api/analyze/",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.csrf_token,
        )

    def test_api_uses_saved_model_and_returns_prediction(self):
        response = self.post_json({"url": "https://www.southbankmosaics.com"})

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn(result["prediction"], {"phishing", "legitimate"})
        self.assertEqual(result["label"], result["prediction"])
        self.assertRegex(result["model_version"], r"^[0-9a-f]{12}$")
        self.assertGreaterEqual(result["phishing_probability"], 0)
        self.assertLessEqual(result["phishing_probability"], 1)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertEqual(result["ai_model"]["algorithm"], "LogisticRegression")
        self.assertIsInstance(result["findings"], list)

    def test_known_phishing_list_endpoint_returns_authoritative_domains(self):
        response = self.client.get("/api/known-phishing-domains/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()["domains"]), KNOWN_PHISHING_DOMAINS)

    def test_nigerian_legitimate_dataset_uses_project_label_mapping(self):
        dataset_path = PROJECT_DIR / "dataset" / "nigerian_websites_dataset.csv"
        with dataset_path.open(newline="", encoding="utf-8-sig") as file:
            rows = list(csv.DictReader(file))

        self.assertTrue(rows)
        self.assertSetEqual({row["Label"] for row in rows}, {"1"})

    def test_known_phishing_domain_matches_normalized_exact_host(self):
        urls = (
            "https://paypal-confirm.com",
            "https://www.paypal-confirm.com",
            "http://paypal-confirm.com",
            "https://PAYPAL-CONFIRM.COM",
            "https://paypal-confirm.com.",
        )
        model = get_analyzer().model
        phishing_class_index = list(model.classes_).index(1)
        for url in urls:
            with self.subTest(url=url):
                result = self.post_json({"url": url}).json()
                expected_probability = round(
                    float(model.predict_proba([normalize_model_url(url)])[0][phishing_class_index]),
                    4,
                )
                known_finding = next(
                    finding for finding in result["findings"]
                    if finding["code"] == "known_phishing_domain"
                )

                self.assertEqual(result["prediction"], "phishing")
                self.assertEqual(result["label"], "phishing")
                self.assertEqual(result["classification_source"], "security_rule")
                self.assertEqual(result["phishing_probability"], expected_probability)
                self.assertEqual(known_finding["severity"], "high")
                self.assertIn("paypal-confirm.com", known_finding["message"])
                self.assertGreaterEqual(result["risk_score"], 35)

    def test_known_phishing_matching_is_hostname_exact(self):
        urls = (
            "https://paypal-confirm.com.attacker.com",
            "https://attacker.com/paypal-confirm.com",
        )
        for url in urls:
            with self.subTest(url=url):
                result = self.post_json({"url": url}).json()

                self.assertNotEqual(result["classification_source"], "security_rule")
                self.assertNotIn("known_phishing_domain", {finding["code"] for finding in result["findings"]})

    def test_official_paypal_is_not_in_known_phishing_list(self):
        result = self.post_json({"url": "https://www.paypal.com"}).json()

        self.assertEqual(result["prediction"], "legitimate")
        self.assertEqual(result["classification_source"], "ai_model")
        self.assertNotIn("known_phishing_domain", {finding["code"] for finding in result["findings"]})

    def test_trusted_nsuk_hostname_overrides_prediction_but_preserves_model_probability(self):
        for url in (
            "https://ug.nsuk.edu.ng/",
            "https://UG.NSUK.EDU.NG/",
            "https://ug.nsuk.edu.ng./",
        ):
            with self.subTest(url=url):
                result = self.post_json({"url": url}).json()

                self.assertEqual(result["prediction"], "legitimate")
                self.assertEqual(result["label"], "legitimate")
                self.assertEqual(result["classification_source"], "trusted_institutional_domain")
                self.assertGreater(result["phishing_probability"], 0.5)

    def test_trusted_nsuk_exception_does_not_suppress_security_findings(self):
        result = self.post_json({
            "url": "http://ug.nsuk.edu.ng/",
            "html": "<iframe src='https://example.com'></iframe>",
        }).json()

        codes = {finding["code"] for finding in result["findings"]}
        self.assertEqual(result["prediction"], "legitimate")
        self.assertIn("no_https", codes)
        self.assertIn("iframe_present", codes)

    def test_nsuk_attacker_suffix_is_not_trusted(self):
        result = self.post_json({"url": "https://ug.nsuk.edu.ng.attacker.com/"}).json()

        self.assertEqual(result["classification_source"], "security_rule")
        self.assertEqual(result["prediction"], "phishing")
        self.assertEqual(result["label"], "phishing")
        self.assertIn("nsuk_lookalike", {finding["code"] for finding in result["findings"]})

    def test_nsuk_lookalikes_are_classified_as_phishing(self):
        urls = (
            "https://www.ug.nsuuk.edu.ng",
            "https://ug.nsuuk.edu.ng",
            "https://ug.nnsuk.edu.ng",
            "https://ug.nssuk.edu.ng",
            "https://ug.nsukk.edu.ng",
            "https://og.nsuk.edu.ng",
            "https://ug.nuk.edu.ng",
            "https://gu.nsuk.edu.ng",
        )
        for url in urls:
            with self.subTest(url=url):
                result = self.post_json({"url": url}).json()

                self.assertEqual(result["prediction"], "phishing")
                self.assertEqual(result["label"], "phishing")
                self.assertEqual(result["classification_source"], "security_rule")
                self.assertIn("nsuk_lookalike", {finding["code"] for finding in result["findings"]})
                self.assertGreaterEqual(result["risk_score"], 35)
                self.assertGreaterEqual(result["phishing_probability"], 0)
                self.assertLessEqual(result["phishing_probability"], 1)

    def test_nsuk_lookalike_rule_uses_hostname_not_path_and_handles_nested_host(self):
        nested_host = self.post_json({"url": "https://ug.nsuk.edu.ng.attacker.com"}).json()
        path_only = self.post_json({"url": "https://attacker.com/ug.nsuk.edu.ng"}).json()
        unrelated = self.post_json({"url": "https://nsuk-example.com"}).json()

        self.assertEqual(nested_host["classification_source"], "security_rule")
        self.assertIn("nsuk_lookalike", {finding["code"] for finding in nested_host["findings"]})
        self.assertNotEqual(path_only["classification_source"], "trusted_institutional_domain")
        self.assertNotIn("nsuk_lookalike", {finding["code"] for finding in path_only["findings"]})
        self.assertNotEqual(unrelated["classification_source"], "security_rule")
        self.assertNotIn("nsuk_lookalike", {finding["code"] for finding in unrelated["findings"]})

    def test_unrelated_url_keeps_model_classification(self):
        result = self.post_json({"url": "https://www.southbankmosaics.com"}).json()

        expected_prediction = "phishing" if result["phishing_probability"] >= 0.5 else "legitimate"
        self.assertEqual(result["classification_source"], "ai_model")
        self.assertEqual(result["prediction"], expected_prediction)
        self.assertEqual(result["label"], expected_prediction)

    def test_invalid_url_is_rejected(self):
        response = self.post_json({"url": "javascript:alert(1)"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_www_and_apex_hosts_share_model_score(self):
        www_result = self.post_json({"url": "https://www.facebook.com"}).json()
        apex_result = self.post_json({"url": "https://facebook.com"}).json()

        self.assertEqual(www_result["phishing_probability"], apex_result["phishing_probability"])
        self.assertEqual(www_result["risk_score"], apex_result["risk_score"])
        self.assertNotIn("brand_lookalike", {finding["code"] for finding in www_result["findings"]})

    def test_brand_lookalike_adds_security_finding_and_risk(self):
        result = self.post_json({"url": "https://www.g00gle.com"}).json()

        self.assertIn("brand_lookalike", {finding["code"] for finding in result["findings"]})
        self.assertEqual(result["findings_risk_score"], 35)
        self.assertGreaterEqual(result["risk_score"], 35)

    def test_high_severity_brand_lookalikes_override_low_model_probability(self):
        urls = (
            "https://www.g00gle.com",
            "https://www.y0utube.com",
            "https://amaz0n.com",
        )
        for url in urls:
            with self.subTest(url=url):
                result = self.post_json({"url": url}).json()

                self.assertEqual(result["prediction"], "phishing")
                self.assertEqual(result["label"], "phishing")
                self.assertEqual(result["classification_source"], "security_rule")
                self.assertLess(result["phishing_probability"], 0.5)
                self.assertGreaterEqual(result["risk_score"], 35)
                self.assertIn("brand_lookalike", {finding["code"] for finding in result["findings"]})

    def test_official_brand_hosts_remain_legitimate(self):
        for url in (
            "https://www.google.com",
            "https://www.youtube.com",
            "https://www.amazon.com",
        ):
            with self.subTest(url=url):
                result = self.post_json({"url": url}).json()

                self.assertEqual(result["prediction"], "legitimate")
                self.assertEqual(result["classification_source"], "ai_model")
                self.assertNotIn("brand_lookalike", {finding["code"] for finding in result["findings"]})

    def test_non_brand_high_severity_finding_does_not_override_model(self):
        result = self.post_json({
            "url": "https://www.southbankmosaics.com",
            "html": "<form action='https://other.example/collect'></form>",
        }).json()

        self.assertEqual(result["prediction"], "legitimate")
        self.assertEqual(result["classification_source"], "ai_model")
        self.assertIn("external_form_target", {finding["code"] for finding in result["findings"]})
        self.assertGreaterEqual(result["findings_risk_score"], 35)

    def test_youtube_lookalike_adds_security_finding(self):
        result = self.post_json({"url": "https://www.y0utube.com"}).json()

        self.assertIn("brand_lookalike", {finding["code"] for finding in result["findings"]})
        self.assertEqual(result["findings_risk_score"], 35)
        self.assertGreaterEqual(result["risk_score"], 35)

    def test_api_requires_csrf_token(self):
        client = Client(enforce_csrf_checks=True)

        response = client.post(
            "/api/analyze/",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
