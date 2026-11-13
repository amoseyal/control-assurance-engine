
"""Tests for assessment workspace application logic
and its Data Transfer Objects (DTOs).
"""
import pytest

from datetime import date

from src.assessment_service import create_assessment
from src.assessment_models import(
    Assessment,
    ControlAssessment,
    Finding,
)
from src.assessment_workspace import (
    AssessmentSummary,
    get_assessment_summaries,
    get_assessment_detail,
    AssessmentDetail,
)


def test_get_assessment_summaries_returns_sorted_dtos(tmp_path):
    """Verify that saved assessment records are converted
    into correctly populated and sorted summary DTOs.
    """
    # Create an isolated storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Define two assessments in reverse identifier order.
    assessments = [
        Assessment(
            assessment_id='ASM-2026-002',
            organization='Southridge Technologies',
            assessor='Security Analyst',
            assessment_date=date(2026, 11, 5),
            framework='ISO/IEC 27001:2022',
            scope='Information security management system',
        ),
        Assessment(
            assessment_id='ASM-2026-001',
            organization='Northstar BuildCo',
            assessor='Security Analyst',
            assessment_date=date(2026, 11, 1),
            framework='NIST CSF 2.0',
            scope='Enterprise cybersecurity controls',
        )
    ]

    # Persist both records using the assessment service.
    for assessment in assessments:
        create_assessment(
            assessment,
            [],
            [],
            storage_directory,
        )

    # Retrieve the workspace summary DTOs.
    summaries = get_assessment_summaries(storage_directory)

    # Verify the correct number and DTO types.
    assert len(summaries) == 2
    assert all(
        isinstance(summary, AssessmentSummary)
        for summary in summaries
    )

    # Verify alphabetical ordering by assessment identifier.
    assert [
        summary.assessment_id for summary in summaries
    ] == [
        'ASM-2026-001',
        'ASM-2026-002',
    ]

    # Verify that assessment metadata was transferred correctly.
    assert summaries[0] == AssessmentSummary(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Enterprise cybersecurity controls',
    )

    assert summaries[1] == AssessmentSummary(
        assessment_id='ASM-2026-002',
        organization='Southridge Technologies',
        assessment_date=date(2026, 11, 5),
        framework='ISO/IEC 27001:2022',
        scope='Information security management system',
    )

    # Verify that retrieving summaries did not modify storage.
    assert len(list(storage_directory.iterdir())) == 2


def test_get_assessment_summaries_returns_empty_list(tmp_path):
    """Return an empty list when the assessment workspace is empty."""
    summaries = get_assessment_summaries(tmp_path)

    assert summaries == []


def test_get_assessment_detail_returns_saved_assessment(tmp_path):
    """Return the selected assessment in a detail DTO."""
    assessment = Assessment(
        assessment_id="ASSESS-001",
        organization="Example Organization",
        assessor="Test Assessor",
        assessment_date=date(2026, 11, 12),
        framework="NIST CSF 2.0",
        scope="Corporate IT",
    )

    create_assessment(assessment, [], [], tmp_path)

    detail = get_assessment_detail("ASSESS-001", tmp_path)

    assert detail.assessment == assessment
    assert detail.control_assessments == ()
    assert detail.findings == ()


def test_assessment_detail_includes_controls_and_findings(tmp_path):
    """Retrieve an assessment with its control evaluations and findings."""
    assessment = Assessment(
        assessment_id="ASM-2026-001",
        organization="Example Organization",
        assessor="Test Assessor",
        assessment_date=date(2026, 11, 12),
        framework="NIST CSF 2.0",
        scope="Corporate IT",
    )

    control_assessment = ControlAssessment(
        assessment_id="ASM-2026-001",
        control_id="IAM-01",
        assessment_method="MANUAL",
        implementation_status="PARTIALLY_IMPLEMENTED",
        evidence_status="SUFFICIENT",
        evidence_references=["MFA configuration export"],
        observations="Three active accounts lack MFA.",
    )

    finding = Finding(
        finding_id="FND-2026-001",
        assessment_id="ASM-2026-001",
        control_id="IAM-01",
        description="Three active accounts lack MFA.",
        likelihood=4,
        impact=4,
        risk_rationale="Missing MFA increases account compromise risk.",
        recommendation="Enforce MFA for all active accounts.",
    )

    create_assessment(
        assessment,
        [control_assessment],
        [finding],
        tmp_path,
    )

    detail = get_assessment_detail("ASM-2026-001", tmp_path)

    assert detail.assessment == assessment
    assert detail.control_assessments == (control_assessment,)
    assert detail.findings == (finding,)
    assert detail.findings[0].risk_score == 16
    assert detail.total_controls == 1
    assert detail.total_findings == 1


def test_get_assessment_detail_returns_none_for_missing_assessment(tmp_path):
    """Return None when the requested assessment does not exist."""

    detail = get_assessment_detail("ASM-DOES-NOT-EXIST", tmp_path)

    assert detail is None


def test_get_assessment_detail_rejects_invalid_identifier(tmp_path):
    """Reject unsafe assessment identifiers."""

    with pytest.raises(ValueError):
        get_assessment_detail("../secrets", tmp_path)


def test_get_assessment_detail_propagates_unrelated_file_error(
        tmp_path,
        monkeypatch,
):
    """Propagate missing-file errors unrelated to the assessment,"""

    def raise_unrelated_file_error(*args, **kwargs):
        raise FileNotFoundError(
            2,
            "No such file or directory",
            str(tmp_path / "unrelated.json"),
        )

    monkeypatch.setattr(
        "src.assessment_workspace.get_assessment",
        raise_unrelated_file_error,
    )

    with pytest.raises(FileNotFoundError):
        get_assessment_detail("ASM-2026-001", tmp_path)

def test_get_assessment_detail_retuns_none_with_default_directory(
        tmp_path,
        monkeypatch,
):
    """Return None for a missing assessment in the default directory."""

    monkeypatch.setattr(
        "src.assessment_service.get_assessments_directory",
        lambda: tmp_path,
    )

    detail = get_assessment_detail("ASM-DOES-BOT-EXIST")

    assert detail is None


def test_assessment_detail_metrics_with_no_findings():
    """Return zero finding metrics for an assessment without findings."""

    assessment = Assessment(
        assessment_id="ASM-2026-001",
        organization="Example Organization",
        assessor="Test Assessor",
        assessment_date=date(2026, 11, 12),
        framework="NIST CSF 2.0",
        scope="Corporate IT",
    )

    detail = AssessmentDetail(
        assessment=assessment,
        control_assessments=(),
        findings=(),
    )

    assert detail.total_controls == 0
    assert detail.total_findings == 0
    assert detail.findings_by_severity == {
        "LOW": 0,
        "MODERATE": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }


def test_assessment_detail_counts_findings_by_severity():
    """Count multiple findings across all risk severity categories."""

    assessment = Assessment(
        assessment_id="ASM-2026-001",
        organization="Example Organization",
        assessor="Test Assessor",
        assessment_date=date(2026, 11, 12),
        framework="NIST CSF 2.0",
        scope="Corporate IT",
    )

    risk_ratings = (
        (1, 2), # LOW
        (2, 3), # MODERATE
        (4, 4), # HIGH
        (3, 5), # HIGH
        (5, 5), # CRITICAL
    )

    findings = tuple(
        Finding(
            finding_id=f"FND-2026-{index:03d}",
            assessment_id=assessment.assessment_id,
            control_id="IAM-01",
            description=f"Test finding {index}",
            likelihood=likelihood,
            impact=impact,
            risk_rationale="Test risk rationale.",
            recommendation="Test recommendation.",
        )
        for index, (likelihood, impact) in enumerate(
            risk_ratings,
            start=1,
        )
    )

    detail = AssessmentDetail(
        assessment=assessment,
        control_assessments=(),
        findings=findings,
    )

    assert detail.total_findings == 5
    assert detail.findings_by_severity == {
        "LOW": 1,
        "MODERATE": 1,
        "HIGH": 2,
        "CRITICAL": 1,
    }