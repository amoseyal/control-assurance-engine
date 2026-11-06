
'''
AApplication logic for the cybersecurity assessment workspace.

This module defines Data Transfer Objects (DTOs) used to
transfer structured assessment information between the
application's service layer and its future user interface.
'''

from dataclasses import dataclass
from datetime import date

from pathlib import Path

from src.assessment_service import (
    get_assessment,
    list_assessment_ids,
)


@dataclass(frozen=True)
class AssessmentSummary:
    '''
    Data Transfer Object (DTO) representing an assessment
    summary for display in the workspace.

    Contains essential assessment metadata without
    exposing detailed control evaluations or findings.
    '''

    assessment_id: str
    organization: str
    assessment_date: date
    framework: str
    scope: str


def get_assessment_summaries(
    storage_directory: Path | None = None,
) -> list[AssessmentSummary]:
    '''
    Retrieve assessment summary DTOs for the workspace.

    Returns summaries sorted by assessment identifier.
    Each summary contains essential assessment metadata.
    '''

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
