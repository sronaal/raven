import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.validators import validate_url, normalize_url, is_private_ip
from services.header_analyzer import analyze_headers, calculate_security_score
from services.parameter_analyzer import analyze_parameters, detect_parameter_type


class TestValidateUrl:
    def test_valid_https_url(self):
        valid, msg = validate_url("https://example.com")
        assert valid is True

    def test_valid_http_url(self):
        valid, msg = validate_url("http://example.com")
        assert valid is True

    def test_empty_url(self):
        valid, msg = validate_url("")
        assert valid is False
        assert "required" in msg.lower()

    def test_invalid_scheme(self):
        valid, msg = validate_url("ftp://example.com")
        assert valid is False
        assert "scheme" in msg.lower()

    def test_no_hostname(self):
        valid, msg = validate_url("https://")
        assert valid is False

    def test_private_ip_blocked(self):
        valid, msg = validate_url("http://192.168.1.1")
        assert valid is False
        assert "private" in msg.lower()

    def test_localhost_blocked(self):
        valid, msg = validate_url("http://localhost")
        assert valid is False


class TestNormalizeUrl:
    def test_adds_https_scheme(self):
        result = normalize_url("example.com")
        assert result.startswith("https://")

    def test_removes_trailing_slash(self):
        result = normalize_url("https://example.com/")
        assert not result.endswith("/")

    def test_preserves_existing_scheme(self):
        result = normalize_url("http://example.com")
        assert result.startswith("http://")


class TestAnalyzeHeaders:
    def test_missing_all_security_headers(self):
        result = analyze_headers({})
        assert len(result["missing_critical"]) > 0
        assert result["score"] < 50

    def test_all_security_headers_present(self):
        headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        result = analyze_headers(headers)
        assert len(result["missing_critical"]) == 0
        assert result["score"] >= 80

    def test_information_disclosure_detected(self):
        headers = {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/8.0"}
        result = analyze_headers(headers)
        assert len(result["problematic"]) > 0

    def test_cors_wildcard_detected(self):
        headers = {"Access-Control-Allow-Origin": "*"}
        result = analyze_headers(headers)
        assert any("CORS" in p.get("risk", "") for p in result["problematic"])


class TestDetectParameterType:
    def test_integer(self):
        assert detect_parameter_type("42") == "integer"

    def test_float(self):
        assert detect_parameter_type("3.14") == "float"

    def test_boolean(self):
        assert detect_parameter_type("true") == "boolean"

    def test_possible_jwt(self):
        assert detect_parameter_type("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123") == "possible_jwt"

    def test_possible_hash_md5(self):
        assert detect_parameter_type("d41d8cd98f00b204e9800998ecf8427e") == "possible_hash_md5"

    def test_string(self):
        assert detect_parameter_type("hello world") == "string"

    def test_empty(self):
        assert detect_parameter_type("") == "empty"


class TestParameterAnalysis:
    def test_sqli_prone_parameter(self):
        result = analyze_parameters("https://example.com?id=1", {}, "")
        assert len(result["parameters"]) == 1
        assert result["parameters"][0]["risk"] == "HIGH"
        assert "SQL Injection" in result["parameters"][0]["risks"][0]

    def test_xss_prone_parameter(self):
        result = analyze_parameters("https://example.com?search=test", {}, "")
        assert len(result["xss_vectors"]) == 1

    def test_no_parameters(self):
        result = analyze_parameters("https://example.com", {}, "")
        assert len(result["parameters"]) == 0
        assert result["score"] == 100
