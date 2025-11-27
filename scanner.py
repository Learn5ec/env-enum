import re
from urllib.parse import urljoin

import aiohttp

from core.config import (
    ABS_URL_RE, REL_URL_RE, JSON_RE, PARAM_RE,
    API_HINT_RE, SENSITIVE_RE,
)
from core.config import MAX_JS_FETCH_PER_HOST
from core.utils import construct_url

# Optional JS exec engine
try:
    from py_mini_racer import py_mini_racer
    HAS_JS_EXEC = True
except Exception:
    HAS_JS_EXEC = False


class Scanner:
    """
    Contains ALL scanning/extraction logic:
    - HTML scanning
    - JS scanning
    - API-doc detection
    - Parameter extraction
    - JSON references
    - JS dynamic evaluation (exec mode)
    """

    def __init__(self, jsmode="regex"):
        self.jsmode = jsmode
        self.ctx = py_mini_racer.MiniRacer() if HAS_JS_EXEC and jsmode == "exec" else None

    # ==================================================================
    # HTML & Body parsing
    # ==================================================================

    def extract_urls_from_body(self, base_url: str, body: bytes):
        """
        Extracts script src, relative URLs, inline endpoints, etc.
        """
        discovered = set()

        try:
            html = body.decode("utf-8", "ignore")
        except Exception:
            return discovered

        # script src="..."
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            if src.startswith("//"):
                discovered.add(f"{base_url.split(':')[0]}:{src}")
            elif src.startswith("http"):
                discovered.add(src)
            else:
                discovered.add(urljoin(base_url, src))

        # Inline references like "/api/login"
        for m in re.findall(r'["\'](/[^"\']+)["\']', html):
            discovered.add(urljoin(base_url, m))

        return discovered

    def extract_absolute_refs(self, body: bytes):
        """
        Extract HTTP/HTTPS absolute URLs.
        """
        discovered = set()
        for m in ABS_URL_RE.findall(body):
            try:
                discovered.add(m.decode())
            except:
                continue
        return discovered

    def extract_json_refs(self, base_url: str, body: bytes):
        """
        Extract JSON config references.
        """
        discovered = set()
        for m in JSON_RE.findall(body):
            try:
                path = m.decode()
                if path.startswith("/"):
                    discovered.add(urljoin(base_url, path))
                else:
                    discovered.add(urljoin(base_url, "/" + path))
            except:
                continue
        return discovered

    # ==================================================================
    # JS File Extraction
    # ==================================================================

    def extract_js_links(self, base_url: str, body: bytes, headers):
        """
        Extract external JS file references.
        """

        discovered = set()
        ctype = headers.get("Content-Type", "")

        # HTML content
        if b"<script" in body or "text/html" in ctype:
            try:
                html = body.decode("utf-8", "ignore")
            except:
                return discovered

            for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                if src.startswith("//"):
                    scheme = base_url.split(":")[0]
                    discovered.add(f"{scheme}:{src}")
                elif src.startswith("http"):
                    discovered.add(src)
                else:
                    discovered.add(urljoin(base_url, src))

        return discovered

    async def fetch_and_scan_js(self, js_url: str, session: aiohttp.ClientSession):
        """
        Fetch JS file and extract endpoints + params.
        Returns: (endpoints_set, params_set)
        """

        endpoints = set()
        params = set()

        try:
            async with session.get(js_url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return endpoints, params
                body = await resp.read()
        except Exception:
            return endpoints, params

        # -------------------------------
        # Regex extraction (default mode)
        # -------------------------------
        endpoints |= self._extract_js_endpoints(body)
        params |= self._extract_js_params(body)

        # -------------------------------
        # JS execution mode (dynamic)
        # -------------------------------
        if self.jsmode == "exec" and self.ctx:
            text = body.decode("utf-8", "ignore")
            dyn = self._execute_js_and_extract(text)
            endpoints |= dyn

        return endpoints, params

    # -----------------------------
    # JS regex matchers
    # -----------------------------
    def _extract_js_endpoints(self, body: bytes):
        endpoints = set()

        # absolute URLs
        for m in ABS_URL_RE.findall(body):
            try:
                endpoints.add(m.decode())
            except:
                continue

        # relative URLs
        for m in REL_URL_RE.findall(body):
            try:
                endpoints.add(m.decode())
            except:
                continue

        # JSON files
        for m in JSON_RE.findall(body):
            try:
                endpoints.add(m.decode())
            except:
                continue

        # API hints ("/api", "/v1", "/openapi", etc.)
        for m in API_HINT_RE.findall(body):
            try:
                endpoints.add(m.decode())
            except:
                continue

        # Sensitive patterns (token, apikey, etc.)
        for m in SENSITIVE_RE.findall(body):
            try:
                endpoints.add("SENSITIVE:" + m.decode())
            except:
                continue

        return endpoints

    def _extract_js_params(self, body: bytes):
        params = set()
        for m in PARAM_RE.findall(body):
            try:
                params.add(m.decode())
            except:
                continue
        return params

    # ==================================================================
    # JS EXEC (Dynamic string evaluation)
    # ==================================================================

    def _execute_js_and_extract(self, js_text: str):
        """
        Tries to evaluate simple expressions, string concatenations,
        var/const assignments, etc.
        """
        extracted = set()

        if not self.ctx:
            return extracted

        # var x = '...'
        assignments = re.findall(
            r"(?:var|let|const)\s+([A-Za-z0-9_$]+)\s*=\s*([\"'].*?[\"'])\s*;",
            js_text,
            re.S,
        )

        for name, val in assignments:
            try:
                v = self.ctx.eval(val)
                if isinstance(v, str) and ("/" in v or "api" in v or "http" in v):
                    extracted.add(v)
            except Exception:
                continue

        # string concatenations
        exprs = re.findall(
            r"([\"']\/[^\n\"']+[\"'](?:\s*\+\s*[^\n;]+)+)",
            js_text
        )
        for ex in exprs:
            try:
                v = self.ctx.eval(ex)
                if isinstance(v, str):
                    extracted.add(v)
            except Exception:
                continue

        return extracted

    # ==================================================================
    # URL Normalization
    # ==================================================================

    def normalize_js_endpoint(self, base_url: str, endpoint: str):
        """
        Normalizes JS-discovered endpoints to absolute URLs.
        """

        if not endpoint:
            return None

        # Already full URL
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint

        # Sensitive tags
        if endpoint.startswith("SENSITIVE:"):
            return None

        # Relative path
        if endpoint.startswith("/"):
            return urljoin(base_url, endpoint)

        # Just a raw string fragment → ignore
        if "." not in endpoint and "/" not in endpoint:
            return None

        return urljoin(base_url, "/" + endpoint.strip("/"))

    # ==================================================================
    # API Documentation Detection
    # ==================================================================

    def detect_api_docs(self, urls: set):
        """
        Returns URLs that look like OpenAPI/Swagger/GraphQL docs.
        """

        hits = set()
        for u in urls:
            low = u.lower()
            if (
                "/swagger" in low
                or "swagger.json" in low
                or "openapi" in low
                or "openapi.json" in low
                or "/graphql" in low
                or "graphiql" in low
                or "/docs" in low
            ):
                hits.add(u)
        return hits
