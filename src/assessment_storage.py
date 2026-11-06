
# ============================================================
# CONTROL ASSURANCE ENGINE — ASSESSMENT STORAGE
# ============================================================

'''
Provide JSON persistence for cybersecurity assessments.

This module will handle serialization, storage, and
reconstruction of validated assessment records.
'''

import json
import os
import tempfile

from dataclasses import asdict
from datetime import date
from pathlib import Path

from src.assessment_models import (
    Assessment,
    ControlAssessment,
    Finding
)


# Version of the JSON structure used fot complete asessment records.
# Increment this when making incompatible changes to the stored format.
ASSESSMENT_RECORD_SCHEMA_VERSION = 1


def serialize_assessment(assessment: Assessment) -> dict:
    '''
    Convert a validated Assessment into a
    JSON-compatible dictionary.

    Dates are converted to ISO 8601 strings because
    JSON does not support Python date objects.
    '''

    # Convert the dataclass fields into a ditionary.
    assessment_data = asdict(assessment)

    # Convert the assessment date into YYY-MM-DD format.
    assessment_data['assessment_date'] = (
        assessment.assessment_date.isoformat()
    )

    return assessment_data


def deserialize_assessment(assessment_data: dict) -> Assessment:
    '''
    Reconstruct a validated Assessment from a
    JSON-compatible dictionary.

    Convert the ISO 8601 date string back into
    a Python date object.
    '''

    # Ensure the supplied date is a dictionary.
    if not isinstance(assessment_data, dict):
        raise ValueError('Assessment data must be a dictionary.')

    # Create a copy to avoid modufying the original dictionary.
    data = assessment_data.copy()

    # Convert the stored date string into a Python date object.
    try:
        data['assessment_date'] = date.fromisoformat(
            data['assessment_date']
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            'assessment_date must be a valis ISO 8601 date string.'
        ) from exc

    # Reconstruct the Assessment using its existing validation.
    return Assessment(**data)


def serialize_control_assessment(
    control_assessment: ControlAssessment
) -> dict:
    '''
    Convert a validated ControlAssessment into
    a JSON-compatible dictionary.

    Evidence references are converted from an
    immutable tuple into a JSON-compatible list.
    '''

    # Convert the dataclass fields into a dictionary.
    control_data = asdict(control_assessment)

    # Convert the evidence references tuple into a list.
    control_data['evidence_references'] = list(
        control_assessment.evidence_references
    )

    return control_data


def deserialize_control_assessment(
        control_data: dict
    ) -> ControlAssessment:
    '''
    Reconstruct a validated ControlAssessment from
    a JSON-compatible doctionary.

    The ControlAssessment model validates the fields
    and converts evidence references into a tuple.
    '''

    # Ensure the supplied data is a doctionary.
    if not isinstance(control_data, dict):
        raise ValueError(
            'Control assessment data must be a dictionary.'
        )

    # Create a copy to preserve the original dictionary.
    data = control_data.copy()

    # Reconstruct the model using its existing validation.
    return ControlAssessment(**data)


def serialize_finding(finding: Finding) -> dict:
    '''
    Convert a validated Finding into a JSON-compatible
    dictionary.

    Derived risk properties are intentionally excluded
    beacuse they are calculated from likelihood and impact.
    '''

    # Convert the Finding dataclass fields into a dictionary.
    finding_data = asdict(finding)

    return finding_data


def deserialize_finding(finding_data: dict) -> Finding:
    '''
    Reconstruct a validated Finding from a
    JSON-compatible dictionary.

    The Finding model validates all supplied fields
    and recalculates risk properties dynamically.
    '''

    # Ensure the supplied data is a dictionary.
    if not isinstance(finding_data, dict):
        raise ValueError(
            'Finding data must be a dictionary.'
        )

    # Create a copy to preserve the original dictionary.
    data = finding_data.copy()

    # Reconstruct the Finding using its existing validation.
    return Finding(**data)



def save_assessment(
    assessment: Assessment,
    file_path: str | Path,
) -> None:
    '''
    Save a validated Assessment using atomic file creation.

    Write the complete JSON document to a temporary file
    before publishing it to the destination.

    Existing assessment files cannot be overwritten.
    '''

    # Serialize the assessment before accessing the filesystem.
    assessment_data = serialize_assessment(assessment)

    json_content = json.dumps(
        assessment_data,
        indent=4,
        ensure_ascii=False,
    )

    # Resolve the destination and its parent directory.
    path = Path(file_path)
    temporary_path = None

    try:
        # Create a temporary file in the destination directory.
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=path.parent,
            prefix=f'.{path.name}.',
            suffix='.tmp',
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)

            # Write the complete JSON document.
            temporary_file.write(json_content)

            # Flush Python's buffered data to the operating system.
            temporary_file.flush()

            # Request that the operating system sync file data.
            os.fsync(temporary_file.fileno())

        # Atomically publish the completed file.
        # Unlike os.replace(), os.link() rejects existing paths.
        os.link(temporary_path, path)

    finally:
        # Remove the temporary file after success or failure.
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def load_assessment(file_path: str | Path) -> Assessment:
    '''
    Load an Assessment from a JSON file.

    The stored data is deserialized and validated
    before an Assessment object is returned.
    '''

    # Convert the supplied path into a Path object.
    path = Path(file_path)

    # Read and parse the JSON file.
    with path.open('r', encoding='utf-8') as file:
        assessment_data = json.load(file)

    # Reconstruct and validate the Assessment.
    return deserialize_assessment(assessment_data)



def serialize_assessment_record(
    assessment: Assessment,
    control_assessments: list[ControlAssessment],
    findings: list[Finding],
) -> dict:
    '''
    Serialize a complete cybersecurity assessment record.

    Validate relationships and convert the assessment,
    control evaluations, and findings into dictionaries.
    '''

    # Validate relationships before serializing the record.
    validate_assessment_record(
        assessment,
        control_assessments,
        findings
    )

    # Serialize the parent assessment metadata.
    assessment_data = serialize_assessment(assessment)

    # Serialize each control evaluation.
    control_data = [
        serialize_control_assessment(control)
        for control in control_assessments
    ]

    # Serialize each finding.
    finding_data = [
        serialize_finding(finding)
        for finding in findings
    ]

    # Return the complete JSON-compatible record.
    # Include the schema version so future application
    # versions can identify the stored record format.
    return {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': assessment_data,
        'control_assessments': control_data,
        'findings': finding_data
    }


def deserialize_assessment_record(record_data: dict) -> tuple:
    '''
    Reconstruct a complete cybersecurity assessment record.

    Validate each model and enforce relationships between
    the assessment, control evaluations, and findings.
    '''

    # Ensure the supplied record is a dictionary.
    if not isinstance(record_data, dict):
        raise ValueError(
            'Assessment record must be a dictionary.'
        )

    # Verify that the record contains exactly the required fields.
    # Reject missing or unexpected fields before accessing them.
    expected_keys = {
        'schema_version',
        'assessment',
        'control_assessments',
        'findings'
    }

    if set(record_data) != expected_keys:
        raise ValueError(
            'Assessment record contains missing or unexpected sections.'
        )

    # Verify that the schema version is a genuine integer.
    # Boolean values are explicitly rejected because bool
    # is a subclass of int in Python.
    schema_version = record_data['schema_version']

    if type(schema_version) is not int:
        raise ValueError(
            'Assessment record schema_version must be an integer.'
        )

    # Reject records using an unsupported schema version.
    # Future migrations can be implemented here when needed.
    if schema_version != ASSESSMENT_RECORD_SCHEMA_VERSION:
        raise ValueError(
            f'Unsupported assessment record schema version: '
            f'{schema_version}.'
        )

    # Ensure that controls and findings are stored as lists.
    if not isinstance(record_data['control_assessments'], list):
        raise ValueError('Control assessments must be a list.')

    if not isinstance(record_data['findings'], list):
        raise ValueError('Findings must be a list.')

    # Reconstruct the validated assessment metadata.
    assessment = deserialize_assessment(
        record_data['assessment']
    )

    # Reconstruct each validated control evaluation.
    control_assessments = [
        deserialize_control_assessment(control_data)
        for control_data in record_data['control_assessments']
    ]

    # Reconstruct each validated finding.
    findings = [
        deserialize_finding(finding_data)
        for finding_data in record_data['findings']
    ]

    # Validate the reconstructed models directly.
    # This enforces assessment relationships, unique
    # identifiers, and valid finding-to-control references.
    validate_assessment_record(
        assessment,
        control_assessments,
        findings
    )

    # Return the reconstructed models.
    return assessment, control_assessments, findings


def save_assessment_record(
        assessment: Assessment,
        control_assessments: list[ControlAssessment],
        findings: list[Finding],
        file_path: str | Path
) -> None:
    '''
    Save a complete assessment record as JSON

    Validate the record before writing, publish the file
    atomically, and refuse to overwrite an existing file.
    '''

    # Validate relationships and serialize all ocmponents.
    record_data = serialize_assessment_record(
        assessment,
        control_assessments,
        findings
    )

    # Serialize the entire record before creating any files.
    # this prevents invalid JSON data from being partially written.
    json_content = json.dumps(record_data, indent=2)

    # Resolve the destination and temporary=file directory.
    path = Path(file_path)
    temporary_path = None

    try:
        # Create a temporary file in the destination directory
        # so publication occurs on the same filesystem.
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=path.parent,
            prefix=f'.{path.name}.',
            suffix='.tmp',
            delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)

            # Write the complete JSON document and flush it
            # to the filesystem before publication
            temporary_file.write(json_content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        # Atomically publish without overwriting an existing file.
        # A hard link fails if the destination already exists.
        os.link(temporary_path, path)

    finally:
        # REmove the temporary file after either success or failure.
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

def load_assessment_record(
        file_path: str | Path,
) -> tuple[Assessment, list[ControlAssessment], list[Finding]]:
    '''
    Load a complete cybersecurity assessment record from JSON.

    Reconstruct the assessment, control evaluations, and
    findings while enforcing model and relationship validation.
    '''

    # Convert the supplied file path to a Path object.
    path = Path(file_path)

    # Read and parse the stored JSON document.
    with path.open('r', encoding='utf-8') as file:
        record_data = json.load(file)

    # Reconstruct validated models and verify relationships.
    return deserialize_assessment_record(record_data)


def validate_assessment_record(
        assessment: Assessment,
        control_assessments: list[ControlAssessment],
        findings: list[Finding]
) -> None:
    '''
    Validate relationships within a complete assessment record.

    Ensure that controls and findings belong to the assessment,
    identifiers are unique, and findings reference assessed controls.
    '''

    # Verify that every control belongs to the parent assessment.
    for control in control_assessments:
        if control.assessment_id != assessment.assessment_id:
            raise ValueError(
                'Control assessment references a different assessment.'
            )

    # Verify that every finding belongs to the parent assessment.
    for finding in findings:
        if finding.assessment_id != assessment.assessment_id:
            raise ValueError(
                'Finding references a different assessment.'
            )

    # Reject duplicate control identifiers.
    control_ids = [
        control.control_id for control in control_assessments
    ]

    if len(control_ids) != len(set(control_ids)):
        raise ValueError(
            'Duplicate control identifiers are not permitted.'
        )

    # Reject duplicate finding identifiers.
    finding_ids = [
        finding.finding_id
        for finding in findings
    ]

    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError(
            'Duplicate finding identifiers are not permitted.'
        )

    # Ensure every finding references an evaluated control.
    assessed_control_ids = set(control_ids)

    for finding in findings:
        if finding.control_id not in assessed_control_ids:
            raise ValueError(
                f'Finding {finding.finding_id} references '
                f'unassessed control {finding.control_id}.'
            )
