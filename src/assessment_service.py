'''
Application services for managing cybersecurity assessments.

This module coordinates assessment operations while keeping
storage implementation details separate from the user interface.
'''

import re
from pathlib import Path

from src.assessment_config import get_assessments_directory
from src.assessment_models import (
    Assessment,
    ControlAssessment,
    Finding
)
from src.assessment_storage import (
    load_assessment_record,
    save_assessment_record
)


def get_assessment_filename(assessment_id: str) -> str:
    '''
    Generate a sage JSON filename from an assessment identifier.

    Only ASCII letters, digits, hyphens, and underscores
    are permitted. Identifiers must begon with a letter or digit.
    '''

    # Reject values that are not strings or are empty.
    if not isinstance(assessment_id, str) or not assessment_id:
        raise ValueError(
            'assessment_id must be a non-empty string.'
        )
    # Enforce a restricted filename-safe identifier format.
    # fullmatch enfures that the entire identifier is valid.
    if not re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_-]*',
        assessment_id,
        flags=re.ASCII
    ):
        raise ValueError(
            'assessment_id contains invalid filename characters.'
        )

    # Append the JSON extension to the validated identifier.
    return f'{assessment_id}.json'


def get_assessment_path(
        assessment_id: str,
        storage_directory: Path | None = None
) -> Path:
    '''
    Construct the filesystem path for an assessment record.

    Use the configured private protage directory by default.
    Allow an explicit directory for testing or alternative
    storage configurations.
    '''

    # Validate the identifier before using it as a filename.
    filename = get_assessment_filename(assessment_id)

    # Use the configured directory unless one was supplied.
    if storage_directory is None:
        storage_directory = get_assessments_directory()

    # Require a pathlib Path to avoid ambiguous path handling.
    if not isinstance(storage_directory, Path):
        raise ValueError(
            'Storage directory must be a Path object'
        )

    # Construct the path without creating directories of files.
    return storage_directory / filename


def validate_storage_directory(storage_directory: Path) -> None:
    '''
    Validate that the assessment storage directory exists,
    is a directory, and is not itself a symbolic link.

    This is a preliminary safety check. It does not protect
    against concurrent filesystem changes.
    '''

    # Require a pathlib Path object.
    if not isinstance(storage_directory, Path):
        raise ValueError(
            'Storage directory must be a Path object.'
        )

    # Reject a symbolic link, including one pointing
    # to an otherwise valid directory.
    if storage_directory.is_symlink():
        raise ValueError(
            'Storage directory must not be a symbolic link.'
        )

    # Require the directory to exist.
    if not storage_directory.exists():
        raise ValueError(
            'Storage directory does not exist.'
        )

    # Reject regular files and other non-directory objects.
    if not storage_directory.is_dir():
        raise ValueError(
            'Storage path must be a directory.'
        )


def create_assessment(
    assessment: Assessment,
    control_assessments: list[ControlAssessment],
    findings: list[Finding],
    storage_directory: Path | None = None
) -> Path:
    '''
    Create a complete assessment record in private storage.

    Validate the destination directory and assessment
    identifier, then delegate persistence to the storage
    layer. Existing records cannot be overwritten.
    '''

    # Resolve the configured storage directory unless
    # the caller explicitly supplies an alternative.
    if storage_directory is None:
        storage_directory = get_assessments_directory()

    # Verify that the destination exists, is a directory,
    # and is not itself a symbolic link.
    validate_storage_directory(storage_directory)

    # Generate the destination path using the validated
    # assessment identifier.
    file_path = get_assessment_path(
        assessment.assessment_id,
        storage_directory
    )

    # Persist the complete assessment record.
    # The storage layer validates model relationships
    # and publishes the file without overwriting.
    save_assessment_record(
        assessment,
        control_assessments,
        findings,
        file_path
    )

    # Return the location of the newly created record.
    return file_path


def get_assessment(
    assessment_id: str,
    storage_directory: Path | None = None,
) -> tuple[Assessment, list[ControlAssessment], list[Finding]]:
    '''
    Retrieve a saved cybersecurity assessment by its identifier.

    Resolve the private storage location, validate the
    directory, and reconstruct the assessment record
    using the existing persistence layer.
    '''

    # Use the configured storage directory by default.
    if storage_directory is None:
        storage_directory = get_assessments_directory()

    # Verify that the storage location is valid.
    validate_storage_directory(storage_directory)

    # Construct the record path using the validated identifier.
    file_path = get_assessment_path(
        assessment_id,
        storage_directory
    )

    # Load the record and validate its contents.
    assessment, control_assessments, findings = (
        load_assessment_record(file_path)
    )

    # Ensure the stored record matches the requested identifier.
    # This prevents returning a mismatched record if a file
    # has been incorrectly named or its contents modified.
    if assessment.assessment_id != assessment_id:
        raise ValueError(
            'Stored assessment_id does not match the requested assessment_id.'
        )

    # Return the reconstructed assessment and its related records.
    return assessment, control_assessments, findings


def list_assessment_ids(storage_directory: Path | None = None) -> list[str]:
    '''
    Return a sorted list of assessment identifiers found
    in the configured private storage directory.

    Only regular JSON files with valid assessment
    identifiers are included.
    '''

    # Use the configured private storage directory by default.
    if storage_directory is None:
        storage_directory = get_assessments_directory()

    # Validate the storage directory before accessing its contents.
    validate_storage_directory(storage_directory)

    # Collect assessment identifiers from valid JSON filenames.
    assessment_ids = []

    for file_path in storage_directory.iterdir():

        # Ignore symbolic links, including links to regular files.
        if file_path.is_symlink():
            continue

        # Ignore directories and non-JSON files.
        if not file_path.is_file() or file_path.suffix != '.json':
            continue

        # Extract the identifier by removing the JSON extension.
        assessment_id = file_path.stem

        # Ignore filenames that violate our identifier rules.
        try:
            get_assessment_filename(assessment_id)
        except ValueError:
            continue

        assessment_ids.append(assessment_id)

    # Return identifiers in a predictable order.
    return sorted(assessment_ids)
