from django.urls import path, re_path

from django_integration.views import analyze_website, frontend, frontend_asset, known_phishing_domains

urlpatterns = [
    path("", frontend, name="frontend"),
    path("api/analyze/", analyze_website, name="analyze_website"),
    path("api/known-phishing-domains/", known_phishing_domains, name="known_phishing_domains"),
    re_path(r"^(?P<filename>style\.css|script\.js)$", frontend_asset, name="frontend_asset"),
]