"""Smoke tests for the Streamlit assessment workspace."""

from datetime import date
from pathlib import Path

from streamlit.testing.v1 import AppTest

from src.assessment_models import (
    Assessment,
    ControlAssessment,
    Finding,
)
from src.assessment_workspace import (
    AssessmentDetail,
    AssessmentSummary,
)

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"


def test_assessment_workspace_renders():
    """Verify that the assessment workspace loads successfully."""
    app = AppTest.from_file(APP_PATH, default_timeout=10)
    app.run()

    assert not app.exception
    assert app.title[0].value == "Control Assurance Engine"
    assert app.subheader[0].value == "Assessment Workspace"


def test_assessment_workspace_handles_empty_repository(monkeypatch):
    """Verify that the workspace handles an empty assessment repository."""
    monkeypatch.setattr(
        "src.assessment_workspace.get_assessment_summaries",
        list,
    )

    app = AppTest.from_file(APP_PATH, default_timeout=10)
    app.run()

    assert not app.exception
    assert len(app.info) == 1
    assert app.info[0].value == "No saved assessments are available."
    assert len(app.selectbox) == 0


def test_assessment_workspace_displays_assessment(monkeypatch):
    """Verify that the workspace displays an isolated assessment."""
    assessment = Assessment(
        assessment_id="ASM-TEST-001",
        organization="Example Security Corp",
        assessor="Test Assessor",
        assessment_date=date(2026, 11, 13),
        framework="NIST CSF 2.0",
        scope="Identity and Access Management",
    )

    summary = AssessmentSummary(
        assessment_id=assessment.assessment_id,
        organization=assessment.organization,
        assessment_date=assessment.assessment_date,
        framework=assessment.framework,
        scope=assessment.scope,
    )

    detail = AssessmentDetail(
        assessment=assessment,
        control_assessments=(),
        findings=(),
    )

    monkeypatch.setattr(
        "src.assessment_workspace.get_assessment_summaries",
        lambda: [summary],
    )

    monkeypatch.setattr(
        "src.assessment_workspace.get_assessment_detail",
        lambda assessment_id: detail,
    )

    app = AppTest.from_file(APP_PATH, default_timeout=10)
    app.run()

    assert not app.exception
    assert app.selectbox[0].value == summary
    assert any(header.value == "Example Security Corp" for header in app.header)
    assert len(app.metric) == 3
    assert [metric.value for metric in app.metric] == ["0", "0", "0"]


def test_assessment_workspace_displays_security_finding(monkeypatch):
    """Verify that the dashboard displays control and risk information."""
    assessment = Assessment(
        assessment_id="ASM-TEST-002",
        organization="Example Security Corp",
        assessor="Test Assessor",
        assessment_date=date(2026, 11, 13),
        framework="NIST CSF 2.0",
        scope="Identity and Access Management",
    )

    summary = AssessmentSummary(
        assessment_id=assessment.assessment_id,
        organization=assessment.organization,
        assessment_date=assessment.assessment_date,
        framework=assessment.framework,
        scope=assessment.scope,
    )

    control = ControlAssessment(
        assessment_id=assessment.assessment_id,
        control_id="IAM-01",
        assessment_method="MANUAL",
        implementation_status="PARTIALLY_IMPLEMENTED",
        evidence_status="SUFFICIENT",
        evidence_references=["EVD-001"],
        observations="MFA is not enforced for all user accounts.",
    )

    finding = Finding(
        finding_id="FND-TEST-001",
        assessment_id=assessment.assessment_id,
        control_id="IAM-01",
        description="MFA enforcement is incomplete.",
        likelihood=4,
        impact=4,
        risk_rationale="Accounts without MFA face increased compromise risk.",
        recommendation="Enforce MFA for all active user accounts.",
    )

    detail = AssessmentDetail(
        assessment=assessment,
        control_assessments=(control,),
        findings=(finding,),
    )

    monkeypatch.setattr(
        "src.assessment_workspace.get_assessment_summaries",
        lambda: [summary],
    )

    monkeypatch.setattr(
        "src.assessment_workspace.get_assessment_detail",
        lambda assessment_id: detail,
    )

    app = AppTest.from_file(APP_PATH, default_timeout=10)
    app.run()

    assert not app.exception
    assert app.selectbox[0].value == summary

    assert [metric.value for metric in app.metric] == ["1", "1", "1"]

    assert finding.risk_score == 16
    assert finding.risk_severity == "HIGH"

    assert len(app.dataframe) == 2
    assert app.dataframe[0].value.iloc[0]["Control ID"] == "IAM-01"
    assert app.dataframe[1].value.iloc[0]["Risk Score"] == 16
    assert app.dataframe[1].value.iloc[0]["Severity"] == "High"

    assert len(app.expander) == 1
    assert "FND-TEST-001" in app.expander[0].label
