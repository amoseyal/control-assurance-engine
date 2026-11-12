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
    list_assessment_ids
)

from src.assessment_models import(
    Assessment,
    ControlAssessment,
    Finding
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


def get_assessment_detail(
        assessment_id: str,
        storage_directory: Path | None = None
) -> AssessmentDetail:
    """Retrieve complete assessment detail for the workspace.

    Load the assessment Through the existing service layer
    and return its records in a structured Data Transfer Object.
    """

    assessment, control_assessments, findings = get_assessment(
        assessment_id,
        storage_directory
    )

    return AssessmentDetail(
        assessment=assessment,
        control_assessments=tuple(control_assessments),
        findings=tuple(findings)
    )
