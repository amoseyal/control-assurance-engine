"""Tests for assessment reporting and export functionality."""

import pandas as pd

from src.reporting import (
    build_control_finding,
    build_executive_summary,
    build_findings_dataframe,
    build_management_findings,
    export_findings_csv,
    export_management_report,
    format_control_finding,
    format_executive_assessment,
    format_executive_summary,
    format_html_control_outcomes,
    format_html_control_results,
    format_html_evidence_comparison,
    format_html_finding_severity,
    format_html_management_findings,
    format_html_report,
    format_management_findings,
    generate_management_report,
)

# Structured control finding tests


def test_build_iam_01_finding():
    """Verify that IAM-01 findings retain the expected metrics and metadata."""
    # Six active accounts have sufficient evidence for IAM-01 assessment.
    assessable_users = pd.DataFrame(
        [
            {"username": "jcarter"},
            {"username": "mlopez"},
            {"username": "akim"},
            {"username": "dthomas"},
            {"username": "snguyen"},
            {"username": "kpatel"},
        ]
    )

    exceptions = pd.DataFrame([{"username": "mlopez"}, {"username": "snguyen"}])

    # tgreen is excluded from the assessable population because account
    # status is unknown; track this as an evidence-quality issue.
    evidence_issues = pd.DataFrame([{"username": "tgreen"}])

    finding = build_control_finding(
        control_id="IAM-01",
        requirement="All active user accounts must have MFA enabled.",
        assessable_population=assessable_users,
        exceptions=exceptions,
        evidence_issues=evidence_issues,
        nist_csf_function="Protect",
        nist_csf_category="PR.AA",
        nist_csf_subcategory="PR.AA-03",
        nist_csf_category_name=(
            "Identity Management, Authentication, and Access Control"
        ),
        nist_csf_subcategory_outcome=(
            "Users, services, and hardware are authenticated"
        ),
        likelihood=4,
        impact=4,
        finding_description=(
            "Three active user accounts were identified without MFA enabled."
        ),
        recommendation=(
            "Enable MFA for all active user accounts and verify enrollment."
        ),
    )

    assert finding["control_id"] == "IAM-01"
    assert finding["requirement"] == ("All active user accounts must have MFA enabled.")

    assert finding["population_tested"] == 6

    assert finding["exception_count"] == 2

    assert finding["exception_rate"] == 33.3

    assert finding["result"] == "FAIL"

    assert finding["affected_entities"] == ["mlopez", "snguyen"]

    assert finding["evidence_issue_count"] == 1

    assert finding["nist_csf_function"] == "Protect"
    assert finding["nist_csf_category"] == "PR.AA"
    assert finding["nist_csf_subcategory"] == "PR.AA-03"

    assert finding["nist_csf_category_name"] == (
        "Identity Management, Authentication, and Access Control"
    )

    assert finding["nist_csf_subcategory_outcome"] == (
        "Users, services, and hardware are authenticated"
    )

    assert finding["likelihood"] == 4
    assert finding["impact"] == 4
    assert finding["risk_score"] == 16
    assert finding["severity"] == "HIGH"

    assert finding["finding_description"] == (
        "Three active user accounts were identified without MFA enabled."
    )

    assert finding["recommendation"] == (
        "Enable MFA for all active user accounts and verify enrollment."
    )


def test_build_end_01_finding():
    """Verify that END-01 findings can identify affected devices."""
    assessable_population = pd.DataFrame(
        [
            {"device_id": "DEV-001"},
            {"device_id": "DEV-002"},
            {"device_id": "DEV-003"},
            {"device_id": "DEV-004"},
            {"device_id": "DEV-005"},
            {"device_id": "DEV-006"},
        ]
    )

    exceptions = pd.DataFrame([{"device_id": "DEV-002"}, {"device_id": "DEV-005"}])

    # DEV-007 lacks evidence and is tracked separately from exceptions.
    evidence_issues = pd.DataFrame([{"device_id": "DEV-007"}])

    finding = build_control_finding(
        control_id="END-01",
        requirement="Company-managed endpoints must use disk encryption.",
        assessable_population=assessable_population,
        exceptions=exceptions,
        evidence_issues=evidence_issues,
        identifier_column="device_id",
    )

    assert finding["population_tested"] == 6
    assert finding["exception_count"] == 2
    assert finding["exception_rate"] == 33.3
    assert finding["result"] == "FAIL"

    assert finding["affected_entities"] == ["DEV-002", "DEV-005"]

    assert finding["evidence_issue_count"] == 1


def test_build_control_finding_returns_not_assessed_for_zero_population():
    """Verify that an empty population yields NOT ASSESSED rather than PASS."""
    assessable_population = pd.DataFrame()
    exceptions = pd.DataFrame(columns=["username"])
    evidence_issues = pd.DataFrame(columns=["username"])

    finding = build_control_finding(
        control_id="TEST-01",
        requirement="Test control requirement.",
        assessable_population=assessable_population,
        exceptions=exceptions,
        evidence_issues=evidence_issues,
        # An unassessed control must not become an active risk finding.
        likelihood=4,
        impact=5,
    )

    assert finding["result"] == "NOT ASSESSED"

    assert finding["population_tested"] == 0
    assert finding["exception_count"] == 0
    assert finding["exception_rate"] == 0.0

    assert finding["risk_score"] is None
    assert finding["severity"] is None


# Human-readable finding formatter tests


def test_format_control_finding():
    """Verify that structured findings are formatted for human readers."""
    finding = {
        "control_id": "END-01",
        "requirement": ("Company-managed endpoints must use disk encryption."),
        "result": "FAIL",
        "population_tested": 6,
        "exception_count": 2,
        "exception_rate": 33.3,
        "affected_entities": ["DEV-002", "DEV-005"],
        "evidence_issue_count": 1,
        "likelihood": 4,
        "impact": 4,
        "risk_score": 16,
        "severity": "HIGH",
        "finding_description": (
            "Company-managed endpoints were identified without disk encryption."
        ),
        "recommendation": (
            "Enable full-disk encryption on all company-managed endpoints."
        ),
    }

    output = format_control_finding(finding, entity_label="Devices")

    assert "Control ID: END-01" in output
    assert (
        "Requirement: Company-managed endpoints must use disk encryption."
    ) in output
    assert "Result: FAIL" in output
    assert "Population Tested: 6" in output
    assert "Exception Count: 2" in output
    assert "Exception Rate: 33.3%" in output
    assert "Affected Devices: DEV-002, DEV-005" in output
    assert "Evidence Issues: 1" in output

    assert "Likelihood: 4" in output
    assert "Impact: 4" in output
    assert "Risk Score: 16" in output
    assert "Severity: HIGH" in output

    assert (
        "Finding: Company-managed endpoints were identified without disk encryption."
        in output
    )

    assert (
        "Recommendation: Enable full-disk encryption on all "
        "company-managed endpoints." in output
    )


def test_format_control_finding_with_no_affected_entities():
    """Verify that findings without affected entities display "None"."""
    finding = {
        "control_id": "END-02",
        "requirement": (
            "Company-managed endpoints must have endpoint protection enabled."
        ),
        "result": "PASS",
        "population_tested": 7,
        "exception_count": 0,
        "exception_rate": 0.0,
        "affected_entities": [],
        "evidence_issue_count": 0,
    }

    output = format_control_finding(finding, entity_label="Devices")

    assert "Affected Devices: None" in output

    assert "Result: PASS" in output


# Findings DataFrame tests


def test_build_findings_dataframe():
    """Verify that structured findings are combined into a report DataFrame."""
    findings = [
        {
            "control_id": "IAM-01",
            "requirement": "All active user accounts must have MFA enabled.",
            "result": "FAIL",
            "population_tested": 8,
            "exception_count": 3,
            "exception_rate": 37.5,
            "affected_entities": ["mlopez", "jparis", "snguyen"],
            "evidence_issue_count": 2,
        },
        {
            "control_id": "END-02",
            "requirement": (
                "Company-managed endpoints must have endpoint protection enabled."
            ),
            "result": "PASS",
            "population_tested": 7,
            "exception_count": 0,
            "exception_rate": 0.0,
            "affected_entities": [],
            "evidence_issue_count": 0,
        },
    ]

    findings_dataframe = build_findings_dataframe(findings)

    assert len(findings_dataframe) == 2

    assert findings_dataframe["control_id"].tolist() == ["IAM-01", "END-02"]

    assert findings_dataframe["result"].tolist() == ["FAIL", "PASS"]

    assert findings_dataframe["exception_count"].tolist() == [3, 0]

    assert findings_dataframe["affected_entities"].tolist() == [
        "mlopez, jparis, snguyen",
        "",
    ]


# Control result and risk severity tests


def test_passing_control_has_no_finding_severity():
    """Verify that PASS controls have no active severity despite baseline risk."""
    assessable_population = pd.DataFrame(
        [{"username": "jcarter"}, {"username": "akim"}]
    )

    exceptions = pd.DataFrame(columns=["username"])

    evidence_issues = pd.DataFrame(columns=["username"])

    finding = build_control_finding(
        control_id="TEST-01",
        requirement="Test control requirement.",
        assessable_population=assessable_population,
        exceptions=exceptions,
        evidence_issues=evidence_issues,
        likelihood=4,
        impact=4,
    )

    assert finding["result"] == "PASS"

    # A passing control retains baseline ratings but has no active risk.
    assert finding["likelihood"] == 4
    assert finding["impact"] == 4

    assert finding["risk_score"] is None
    assert finding["severity"] is None


# Executive summary tests


def test_build_executive_summary():
    """Verify that control findings are aggregated into executive metrics."""
    findings = [
        {
            "control_id": "IAM-01",
            "result": "FAIL",
            "exception_count": 3,
            "evidence_issue_count": 2,
            "severity": "HIGH",
        },
        {
            "control_id": "END-02",
            "result": "PASS",
            "exception_count": 0,
            "evidence_issue_count": 0,
            "severity": None,
        },
        {
            "control_id": "TPR-01",
            "result": "NOT ASSESSED",
            "exception_count": 0,
            "evidence_issue_count": 1,
            "severity": None,
        },
    ]

    summary = build_executive_summary(findings)

    assert summary["controls_assessed"] == 3
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["not_assessed"] == 1

    # Evidence issues remain separate from confirmed exceptions.
    assert summary["total_exceptions"] == 3
    assert summary["evidence_issues"] == 3

    assert summary["high_findings"] == 1
    assert summary["critical_findings"] == 0


def test_format_executive_summary():
    """Verify that executive metrics are formatted as a management table."""
    summary = {
        "controls_assessed": 7,
        "passed": 1,
        "failed": 6,
        "not_assessed": 0,
        "total_exceptions": 9,
        "evidence_issues": 4,
        "high_findings": 6,
        "critical_findings": 0,
    }

    output = format_executive_summary(summary)

    assert "| Metric | Result |" in output
    assert "| --- | ---: |" in output

    assert "| Controls Evaluated | 7 |" in output
    assert "| Passed | 1 |" in output
    assert "| Failed | 6 |" in output
    assert "| Not Assessed | 0 |" in output
    assert "| Total Exceptions | 9 |" in output
    assert "| Evidence Issues | 4 |" in output
    assert "| High Findings | 6 |" in output
    assert "| Critical Findings | 0 |" in output


def test_format_executive_assessment():
    """Verify that executive metrics are summarized in a concise narrative."""
    summary = {
        "controls_assessed": 7,
        "passed": 1,
        "failed": 6,
        "not_assessed": 0,
        "total_exceptions": 9,
        "evidence_issues": 7,
        "high_findings": 6,
        "critical_findings": 0,
    }

    assessment = format_executive_assessment(summary)

    assert "Six of seven controls evaluated" in assessment

    assert "confirmed exceptions requiring remediation" in assessment

    assert "No critical-severity findings were identified" in assessment
    assert "Six findings were rated High" in assessment


# Management findings tests


def test_build_management_findings():
    """Verify that management findings include confirmed failures only."""
    findings = [
        {
            "control_id": "IAM-01",
            "result": "FAIL",
            "severity": "HIGH",
            "affected_entities": ["mlopez", "snguyen"],
        },
        {
            "control_id": "END-02",
            "result": "PASS",
            "severity": None,
            "affected_entities": [],
        },
        {
            "control_id": "TPR-01",
            "result": "NOT ASSESSED",
            "severity": None,
            "affected_entities": [],
        },
        {
            "control_id": "TPR-02",
            "result": "FAIL",
            "severity": "HIGH",
            "affected_entities": ["VND-002"],
        },
    ]

    management_findings = build_management_findings(findings)

    assert len(management_findings) == 2
    assert management_findings[0]["control_id"] == "IAM-01"
    assert management_findings[1]["control_id"] == "TPR-02"

    assert all(finding["result"] == "FAIL" for finding in management_findings)


def test_format_management_findings():
    """Verify that failed findings are formatted as remediation summaries."""
    management_findings = [
        {
            "control_id": "IAM-01",
            "severity": "HIGH",
            "affected_entities": ["mlopez", "snguyen"],
            "finding_description": (
                "Active user accounts were identified without MFA enabled."
            ),
            "recommendation": (
                "Enable MFA for all active user accounts and verify enrollment."
            ),
        },
        {
            "control_id": "TPR-02",
            "severity": "HIGH",
            "affected_entities": ["VND-002"],
            "finding_description": (
                "Third-party vendors with privileged access were identified "
                "without MFA enabled."
            ),
            "recommendation": (
                "Require MFA for all third-party vendors with privileged access."
            ),
        },
    ]

    output = format_management_findings(management_findings)

    assert "### IAM-01 | HIGH" in output
    assert "### TPR-02 | HIGH" in output

    assert "**Affected:** mlopez, snguyen" in output
    assert "**Affected:** VND-002" in output

    assert (
        "**Finding:** Active user accounts were identified without MFA enabled."
        in output
    )
    assert (
        "**Recommendation:** Enable MFA for all active user accounts "
        "and verify enrollment." in output
    )


# Management report tests


def test_generate_management_report():
    """Verify that metrics and remediation findings form a Markdown report."""
    executive_summary = {
        "controls_assessed": 3,
        "passed": 1,
        "failed": 2,
        "not_assessed": 0,
        "total_exceptions": 3,
        "evidence_issues": 1,
        "high_findings": 2,
        "critical_findings": 0,
    }

    management_findings = [
        {
            "control_id": "IAM-01",
            "severity": "HIGH",
            "affected_entities": ["mlopez", "snguyen"],
            "finding_description": (
                "Active user accounts were identified without MFA enabled."
            ),
            "recommendation": (
                "Enable MFA for all active user accounts and verify enrollment."
            ),
        },
        {
            "control_id": "TPR-02",
            "severity": "HIGH",
            "affected_entities": ["VND-002"],
            "finding_description": (
                "Third-party vendors with privileged access were identified "
                "without MFA enabled."
            ),
            "recommendation": (
                "Require MFA for all third-party vendors with privileged access."
            ),
        },
    ]

    report = generate_management_report(executive_summary, management_findings)

    assert "# Northstar BuildCo" in report
    assert "## Cybersecurity Control Assurance Assessment" in report
    assert "## Executive Summary" in report
    assert "## Findings Requiring Remediation" in report

    assert "| Controls Evaluated | 3 |" in report
    assert "| Passed | 1 |" in report
    assert "| Failed | 2 |" in report

    assert (
        "Two of three controls evaluated resulted in confirmed "
        "exceptions requiring remediation." in report
    )

    assert "No critical-severity findings were identified." in report

    assert (
        "Two findings were rated High based on the defined "
        "Northstar BuildCo risk criteria." in report
    )

    assert "### IAM-01 | HIGH" in report
    assert "### TPR-02 | HIGH" in report
    assert (
        "**Recommendation:** Enable MFA for all active user accounts "
        "and verify enrollment." in report
    )


def test_generate_management_report_includes_assessment_context():
    """Verify that the management report includes assessment context."""
    executive_summary = {
        "controls_assessed": 3,
        "passed": 1,
        "failed": 2,
        "not_assessed": 0,
        "total_exceptions": 3,
        "evidence_issues": 1,
        "high_findings": 2,
        "critical_findings": 0,
    }

    management_findings = []

    report = generate_management_report(
        executive_summary,
        management_findings,
        assessment_date="October 2026",
        assessment_scope=(
            "Identity and Access Management, Endpoint Security, and Third-Party Risk"
        ),
        framework_alignment="NIST Cybersecurity Framework (CSF) 2.0",
    )

    assert "**Assessment Date:** October 2026" in report

    assert (
        "**Assessment Scope:** Identity and Access Management, "
        "Endpoint Security, and Third-Party Risk" in report
    )

    assert "**Framework Alignment:** NIST Cybersecurity Framework (CSF) 2.0" in report


def test_export_management_report(tmp_path):
    """Verify that a Markdown report is written to the specified file."""
    report = (
        "# Northstar BuildCo\n\n"
        "## Cybersecurity Control Assurance Assessment\n\n"
        "## Executive Summary\n\n"
        "Controls Evaluated: 7"
    )

    # Keep exported test output isolated from the project output folder.
    output_file = tmp_path / "management_report.md"

    export_management_report(report, output_file)

    assert output_file.exists()

    assert output_file.read_text() == report


# Findings CSV export tests


def test_export_findings_csv(tmp_path):
    """Verify that findings can be exported to a CSV file."""
    findings_dataframe = pd.DataFrame(
        [
            {
                "control_id": "IAM-01",
                "result": "FAIL",
                "population_tested": 8,
                "exception_count": 3,
                "exception_rate": 37.5,
                "evidence_issue_count": 2,
            },
            {
                "control_id": "END-02",
                "result": "PASS",
                "population_tested": 7,
                "exception_count": 0,
                "exception_rate": 0.0,
                "evidence_issue_count": 0,
            },
        ]
    )

    output_file = tmp_path / "control_findings.csv"

    export_findings_csv(findings_dataframe, output_file)

    assert output_file.exists()

    exported_findings = pd.read_csv(output_file)

    assert len(exported_findings) == 2

    assert exported_findings["control_id"].tolist() == ["IAM-01", "END-02"]

    assert exported_findings["result"].tolist() == ["FAIL", "PASS"]


# HTML management report tests


def test_format_html_report_returns_complete_html_document():
    """HTML management report should return a complete HTML document."""
    report = format_html_report([])

    assert "<!DOCTYPE html>" in report
    assert '<html lang="en">' in report
    assert "<title>Control Assurance Engine | Management Report</title>" in report
    assert '<h1><svg class="report-icon"' in report
    assert "Control Assurance Engine</h1>" in report

    assert "Northstar BuildCo" in report
    assert "</html>" in report


def test_format_html_report_uses_executive_summary_metrics():
    """HTML report should display metrics derived from control findings."""
    findings = [
        {
            "control_id": "END-02",
            "requirement": (
                "Company-managed endpoints must have endpoint protection enabled."
            ),
            "nist_csf_subcategory": "PR.PS-05",
            "result": "PASS",
            "population_tested": 7,
            "exception_count": 0,
            "exception_rate": 0.0,
            "evidence_issue_count": 0,
            "risk_score": None,
            "severity": None,
        },
        {
            "control_id": "IAM-01",
            "requirement": "All active user accounts must have MFA enabled.",
            "nist_csf_subcategory": "PR.AA-03",
            "result": "FAIL",
            "population_tested": 8,
            "exception_count": 2,
            "exception_rate": 25.0,
            "evidence_issue_count": 2,
            "risk_score": 16,
            "severity": "HIGH",
            "finding_description": (
                "Active user accounts were identified without MFA enabled."
            ),
            "affected_entities": ["mlopez", "jparis"],
            "recommendation": (
                "Enable MFA for all active user accounts and verify enrollment."
            ),
        },
    ]

    report = format_html_report(findings)

    assert "<h2>" in report
    assert "Control Results</h2>" in report
    assert "END-02" in report
    assert "IAM-01" in report
    assert "PR.PS-05" in report
    assert "PR.AA-03" in report

    report = format_html_report(findings)

    assert "2" in report
    assert "Controls Evaluated" in report

    assert "1" in report
    assert "Passed" in report
    assert "Failed" in report

    assert "2" in report
    assert "Total Exceptions" in report

    assert "2" in report
    assert "Evidence Issues" in report

    assert "1" in report
    assert "High Findings" in report

    assert "0" in report
    assert "Critical Findings" in report


def test_format_html_control_results_pass_has_no_active_risk():
    """PASS controls should not be assigned an active risk severity or score."""
    findings = [
        {
            "control_id": "END-02",
            "requirement": (
                "Company-managed endpoints must have endpoint protection enabled."
            ),
            "nist_csf_subcategory": "PR.PS-05",
            "result": "PASS",
            "population_tested": 7,
            "exception_count": 0,
            "exception_rate": 0.0,
            "evidence_issue_count": 0,
            "risk_score": None,
            "severity": None,
        }
    ]

    report = format_html_control_results(findings)

    assert "END-02" in report
    assert "PASS" in report
    assert "PR.PS-05" in report

    # PASS does not imply LOW risk; no active risk rating is assigned.
    assert report.count("N/A") == 2


def test_format_html_control_results_includes_control_data():
    """HTML control results should display assessment and risk data."""
    findings = [
        {
            "control_id": "IAM-01",
            "requirement": "All active user accounts must have MFA enabled.",
            "nist_csf_subcategory": "PR.AA-03",
            "result": "FAIL",
            "population_tested": 8,
            "exception_count": 3,
            "exception_rate": 37.5,
            "evidence_issue_count": 2,
            "risk_score": 16,
            "severity": "HIGH",
        }
    ]

    report = format_html_control_results(findings)

    assert "IAM-01" in report
    assert "All active user accounts must have MFA enabled." in report

    assert "FAIL" in report
    assert "HIGH" in report
    assert "PR.AA-03" in report

    assert "37.5%" in report
    assert "Population Tested" in report
    assert "Exceptions" in report
    assert "Evidence Issues" in report
    assert "Risk Score" in report


def test_format_html_management_findings_includes_remediation_details():
    """HTML management findings should include actionable remediation data."""
    management_findings = [
        {
            "control_id": "IAM-01",
            "severity": "HIGH",
            "finding_description": (
                "Active user accounts were identified without MFA enabled."
            ),
            "affected_entities": ["mlopez", "jparis"],
            "recommendation": (
                "Enable MFA for all active user accounts and verify enrollment."
            ),
        }
    ]

    report = format_html_management_findings(management_findings)

    assert "IAM-01" in report
    assert "HIGH" in report
    assert "Active user accounts were identified without MFA enabled." in report
    assert "mlopez, jparis" in report
    assert "Enable MFA for all active user accounts" in report
    assert "Finding" in report
    assert "Affected" in report
    assert "Recommendation" in report


def test_format_html_control_outcomes_uses_summary_metrics():
    """Control-outcome visual should use existing executive metrics."""
    summary = {"controls_assessed": 7, "passed": 1, "failed": 6, "not_assessed": 0}

    report = format_html_control_outcomes(summary)

    assert "Control Outcomes" in report
    assert "Passed" in report
    assert "Failed" in report
    assert "Not Assessed" in report
    assert "width: 14.3%" in report
    assert "width: 85.7%" in report
    assert "width: 0.0%" in report


def test_format_html_finding_severity_uses_summary_metrics():
    """Finding-severity visual should use existing severity metrics."""
    summary = {"high_findings": 6, "critical_findings": 0}

    report = format_html_finding_severity(summary)

    assert "Finding Severity" in report
    assert "High" in report
    assert "Critical" in report
    assert "width: 100.0%" in report
    assert "width: 0.0%" in report


def test_format_html_evidence_comparison_uses_finding_counts():
    """Evidence comparison should preserve exception and evidence counts."""
    findings = [
        {"control_id": "IAM-01", "exception_count": 3, "evidence_issue_count": 2},
        {"control_id": "IAM-02", "exception_count": 1, "evidence_issue_count": 0},
    ]

    report = format_html_evidence_comparison(findings)

    assert "Exceptions vs. Evidence Issues by Control" in report
    assert "IAM-01" in report
    assert "IAM-02" in report
    assert "Exceptions" in report
    assert "Evidence Issues" in report

    # Bars are normalized to the largest count in the findings.
    assert "width: 100.0%" in report
    assert "width: 66.7%" in report
    assert "width: 33.3%" in report
    assert "width: 0.0%" in report


def test_format_html_report_includes_assessment_context():
    """HTML management report should include assessment context."""
    report = format_html_report(
        [],
        assessment_date="October 2026",
        assessment_scope=(
            "Identity and Access Management, Endpoint Security, and Third-Party Risk"
        ),
        framework_alignment="NIST Cybersecurity Framework (CSF) 2.0",
    )

    assert "October 2026" in report
    assert (
        "Identity and Access Management, Endpoint Security, and Third-Party Risk"
    ) in report
    assert "NIST Cybersecurity Framework (CSF) 2.0" in report
