"""
AApplication logic for the cybersecurity assessment workspace.

This module defines Data Transfer Objects (DTOs) used to
transfer structured assessment information between the
application's service layer and its future user interface.
"""

from dataclasses import dataclass
from datetime import date

from pathlib import Path

from src.assessment_service import (
    get_assessment,
    list_assessment_ids,
    get_assessment_path,
)

from src.assessment_models import(
    Assessment,
    ControlAssessment,
    Finding,
)


@dataclass(frozen=True)
class AssessmentSummary:
    """
    Data Transfer Object (DTO) representing an assessment
    summary for display in the workspace.

    Contains essential assessment metadata without
    exposing detailed control evaluations or findings.
    """

    assessment_id: str
    organization: str
    assessment_date: date
    framework: str
    scope: str


def get_assessment_summaries(
    storage_directory: Path | None = None,
) -> list[AssessmentSummary]:
    """
    Retrieve assessment summary DTOs for the workspace.

    Returns summaries sorted by assessment identifier.
    Each summary contains essential assessment metadata.
    """

    # Discover saved assessment identifiers.
    assessment_ids = list_assessment_ids(storage_directory)

    # Collect summary DTOs for the workspace.
    summaries = []

    for assessment_id in assessment_ids:

        # Retrieve the validated assessment record.
        assessment, _, _ = get_assessment(
            assessment_id,
            storage_directory
        )

        # Convert assessment metadata into a summary DTO.
        summary = AssessmentSummary(
            assessment_id=assessment.assessment_id,
            organization=assessment.organization,
            assessment_date=assessment.assessment_date,
            framework=assessment.framework,
            scope=assessment.scope
        )

        summaries.append(summary)

    return summaries


@dataclass(frozen=True)
class AssessmentDetail:
    """Represent the complete details of a selected assessment.

    Provide assessment metadata, control evaluations, and
    security findings to the workspace user interface.
    """

    assessment: Assessment
    control_assessments: tuple[ControlAssessment, ...]
    findings: tuple[Finding, ...]

    @property
    def total_controls(self) -> int:
        """Return the number of evaluated controls."""
        return len(self.control_assessments)

    @property
    def total_findings(self) -> int:
        """Return the number of security findings."""
        return len(self.findings)

    @property
    def findings_by_severity(self) -> dict[str,int]:
        """Return the number of findings in each risk severity category."""

        counts = {
            "LOW": 0,
            "MODERATE": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        for finding in self.findings:
            counts[finding.risk_severity] += 1

        return counts


def get_assessment_detail(
    assessment_id: str,
    storage_directory: Path | None = None,
) -> AssessmentDetail | None:
    """Retrieve complete assessment details for the workspace.

    Load the assessment through the existing service layer
    and return its records in a structured Data Transfer Object.

    Return None if the requested assessment does not exist.
    """

    try:
        assessment, control_assessments, findings = get_assessment(
            assessment_id,
            storage_directory,
        )
    except FileNotFoundError as exc:
        expected_path = get_assessment_path(
            assessment_id,
            storage_directory,
        )

        if exc.filename is None or Path(exc.filename) != expected_path:
            raise

        return None

    return AssessmentDetail(
        assessment=assessment,
        control_assessments=tuple(control_assessments),
        findings=tuple(findings),
    )
