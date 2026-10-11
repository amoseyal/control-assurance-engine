from html import escape

from src.reporting import (
    format_html_control_results,
    format_html_evidence_comparison,
    format_html_report
)


def test_control_results_escape_html():
    """
    Verify that potentially malicious assessment data is
    escaped before being inserted into the HTML report.
    """

    malicious_input = '<script>alert("XSS")</script>'

    finding = {
        "control_id": malicious_input,
        "result": "FAIL",
        "severity": "HIGH",
        "requirement": malicious_input,
        "nist_csf_subcategory": "PR.AA-01",
        "population_tested": 10,
        "exception_count": 2,
        "exception_rate": 20.0,
        "evidence_issue_count": 1,
        "risk_score": 8,
    }

    html = format_html_control_results([finding])

    # Malicious markup must never appear unescaped.
    assert malicious_input not in html

    # The original content should remain visible as text.
    assert escape(malicious_input, quote=True) in html

    # Legitimate report structure must remain intact.
    assert '<article class="control-card control-fail">' in html
    assert "severity-badge severity-high" in html


from src.reporting import format_html_management_findings


def test_management_findings_escape_html():
    """
    Verify that management findings safely escape
    potentially malicious assessment data.
    """

    malicious_input = "<img src=x onerror=alert(1)>"

    finding = {
        "control_id": malicious_input,
        "severity": "HIGH",
        "finding_description": malicious_input,
        "affected_entities": ["Server-01", malicious_input],
        "recommendation": malicious_input,
    }

    html = format_html_management_findings([finding])

    # Malicious HTML must not appear as executable markup.
    assert malicious_input not in html

    # The original content must be preserved as escaped text.
    assert escape(malicious_input, quote=True) in html

    # Verify the affected entities remain readable.
    assert "Server-01" in html

    # Verify the expected report structure remains intact.
    assert '<article class="finding-card">' in html
    assert "severity-badge severity-high" in html


def test_evidence_comparison_escapes_html():
    """
    Verify that control identifiers are HTML-escaped
    in the evidence comparison visualization.

    Confirm that escaping preserves the chart structure
    and does not modify assessment metrics.
    """

    malicious_input = '<script>alert("XSS")</script>'

    findings = [
        {"control_id": malicious_input, "exception_count": 3, "evidence_issue_count": 2}
    ]

    html = format_html_evidence_comparison(findings)

    # Raw malicious markup must not appear in the output.
    assert malicious_input not in html

    # The control identifier must remain visible as escaped text.
    assert escape(malicious_input, quote=True) in html

    # Verify that the visualization structure remains intact.
    assert '<div class="comparison-row">' in html
    assert "comparison-bar comparison-exception" in html
    assert "comparison-bar comparison-evidence" in html

    # Confirm that the underlying assessment metrics are preserved.
    assert "<strong>3</strong>" in html
    assert "<strong>2</strong>" in html


def test_html_report_escapes_assessment_metadata():
    """
    Verify that assessment metadata is HTML-escaped
    before being inserted into the management report.

    Ensure malicious markup is rendered as text while
    preserving the report's existing HTML structure.
    """

    malicious_input = '<script>alert("XSS")</script>'

    html = format_html_report(
        findings=[],
        assessment_date=malicious_input,
        assessment_scope=malicious_input,
        framework_alignment=malicious_input,
    )

    # Raw malicious markup must never appear in the report.
    assert malicious_input not in html

    # All three metadata fields must preserve the escaped text.
    escaped_input = escape(malicious_input, quote=True)
    assert html.count(escaped_input) == 3

    # The generated document must retain its HTML structure.
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html
