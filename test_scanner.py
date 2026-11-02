import pytest
from app.scanner import validate_scope, header_findings

def test_localhost_scope():
    validate_scope("http://localhost:8000")

def test_unsupported_scheme_rejected():
    with pytest.raises(ValueError):
        validate_scope("ftp://localhost/file")

def test_header_review_reports_missing_headers():
    findings = header_findings({})
    assert len(findings) >= 5
    assert any("Content-Security-Policy" in x.title for x in findings)
