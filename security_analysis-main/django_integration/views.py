from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import FileResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from phishing_detector.analyzer import KNOWN_PHISHING_DOMAINS, PhishingAnalyzer

logger = logging.getLogger(__name__)
FRONTEND_DIR = settings.BASE_DIR / "phishing detection website"


@lru_cache(maxsize=1)
def get_analyzer() -> PhishingAnalyzer:
    return PhishingAnalyzer(settings.PHISHING_MODEL_PATH)


@ensure_csrf_cookie
@require_GET
def frontend(request):
    return FileResponse((FRONTEND_DIR / "index.html").open("rb"), content_type="text/html")


@require_GET
def frontend_asset(request, filename: str):
    from django.http import Http404
    from django.views.static import serve

    if filename not in {"script.js", "style.css"}:
        raise Http404
    return serve(request, filename, document_root=str(FRONTEND_DIR))


@require_GET
def known_phishing_domains(request):
    return JsonResponse({"domains": sorted(KNOWN_PHISHING_DOMAINS)})


@csrf_protect
@require_POST
def analyze_website(request):
    try:
        if request.content_type != "application/json":
            return JsonResponse({"error": "Content-Type must be application/json"}, status=415)
        payload = json.loads(request.body.decode("utf-8"))
    except RequestDataTooBig:
        return JsonResponse({"error": "Request body is too large"}, status=413)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"error": "Request body must be valid JSON"}, status=400)

    if not isinstance(payload, dict):
        return JsonResponse({"error": "JSON body must be an object"}, status=400)
    if not isinstance(payload.get("url"), str):
        return JsonResponse({"error": "url must be a non-empty string"}, status=400)
    page_html = payload.get("html")
    if page_html is not None and (not isinstance(page_html, str) or len(page_html) > 50000):
        return JsonResponse({"error": "html must be a string no longer than 50000 characters"}, status=400)

    try:
        result = get_analyzer().analyze(payload["url"], page_html)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except FileNotFoundError:
        return JsonResponse({"error": "The phishing model is not available"}, status=503)
    except Exception:
        logger.exception("Website analysis failed")
        return JsonResponse({"error": "Analysis failed"}, status=500)

    response = JsonResponse(result)
    response["Cache-Control"] = "no-store"
    return response


