
"""Tests for assessment workspace application logic
and its Data Transfer Objects (DTOs).
"""
from datetime import date

from src.assessment_models import Assessment
from src.assessment_service import create_assessment
from src.assessment_workspace import (
    AssessmentSummary,
    get_assessment_summaries,
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
        ),
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