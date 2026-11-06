
'''
Tests for cybersecurity assessment service operations.
'''

from datetime import date
from pathlib import Path

import pytest
import json

from src.assessment_config import get_assessments_directory
from src.assessment_models import(
    Assessment,
    ControlAssessment,
    Finding
)
from src.assessment_service import(
    get_assessment_filename,
    get_assessment_path,
    validate_storage_directory,
    create_assessment,
    get_assessment,
    list_assessment_ids
)
from src.assessment_storage import load_assessment_record


@pytest.mark.parametrize(
    'assessment_id, expected_filename',
    [
        ('ASM-2026-001', 'ASM-2026-001.json'),
        ('ASM_2026_001', 'ASM_2026_001.json'),
        ('Assessment123', 'Assessment123.json'),
        ('12345', '12345.json'),
        ('A', 'A.json')
    ]
)
def test_get_assessment_filename_accepts_valid_identifiers(
    assessment_id,
    expected_filename,
):
    '''
    Verify that valid assessment identifiers produce
    the expected JSON filenames.
    '''

    assert get_assessment_filename(assessment_id) == expected_filename


@pytest.mark.parametrize(
    'assessment_id',
    [
        '',
        None,
        123,
        True,
        [],
        {}
    ]
)
def test_get_assessment_filename_rejects_invalid_inputs(
    assessment_id
):
    '''
    Verify that empty identifiers and non-string
    values are rejected.
    '''

    with pytest.raises(
        ValueError,
        match='assessment_id must be a non-empty string'
    ):
        get_assessment_filename(assessment_id)


@pytest.mark.parametrize(
    'assessment_id',
    [
        '../private',
        '../../secrets',
        'ASM/2026/001',
        r'ASM\2026\001',
        'ASM.2026.001',
        '.hidden',
        'ASM 2026 001',
        '-ASM-001',
        '_ASM-001',
        'ASM-001\n',
        'ASM-001.json'
    ]
)
def test_get_assessment_filename_rejects_unsafe_identifiers(
    assessment_id,
):
    '''
    Verify that identifiers containing path separators,
    traversal sequences, or disallowed characters
    cannot become assessment filenames.
    '''

    with pytest.raises(
        ValueError,
        match='assessment_id contains invalid filename characters'
    ):
        get_assessment_filename(assessment_id)


def test_get_assessment_path_uses_default_directory():
    '''
    Verify that assessment paths use the configured
    private storage directory by default.
    '''

    expected_path = (
        get_assessments_directory() / 'ASM-2026-001.json'
    )

    assert get_assessment_path('ASM-2026-001') == expected_path


def test_get_assessment_path_accepts_custom_directory(tmp_path):
    '''
    Verify that callers can provide an alternative
    storage directory without creating any files.
    '''

    storage_directory = tmp_path / 'assessments'

    result = get_assessment_path(
        'ASM-2026-001',
        storage_directory,
    )

    assert result == storage_directory / 'ASM-2026-001.json'
    assert not storage_directory.exists()


@pytest.mark.parametrize(
    'assessment_id',
    [
        '../secrets',
        'ASM/2026/001',
        '',
        None
    ]
)
def test_get_assessment_path_rejects_invalid_identifiers(
    assessment_id,
    tmp_path,
):
    '''
    Verify that unsafe assessment identifiers
    cannot be converted into filesystem paths.
    '''

    with pytest.raises(ValueError):
        get_assessment_path(assessment_id, tmp_path)


@pytest.mark.parametrize(
    'storage_directory',
    [
        'data/assessments',
        123,
        []
    ]
)
def test_get_assessment_path_rejects_invalid_directory_types(
    storage_directory,
):
    '''
    Verify that storage directories must be Path objects.
    '''

    with pytest.raises(
        ValueError,
        match='Storage directory must be a Path object'
    ):
        get_assessment_path(
            'ASM-2026-001',
            storage_directory
        )


def test_validate_storage_directory_accepts_valid_directory(tmp_path):
    '''
    Verify that an existing regular directory is accepted.
    '''

    # pytest provides an existing temporary directory.
    assert validate_storage_directory(tmp_path) is None


def test_validate_storage_directory_rejects_missing_directory(tmp_path):
    '''
    Verify that a nonexistent storage directory is rejected.
    '''

    storage_directory = tmp_path / 'missing-assessments'

    with pytest.raises(
        ValueError,
        match='Storage directory does not exist.'
    ):
        validate_storage_directory(storage_directory)

    # Validation must not create the missing directory.
    assert not storage_directory.exists()


def test_validate_storage_directory_rejects_regular_file(tmp_path):
    '''
    Verify that a regular file cannot be used as
    the assessment storage directory.
    '''

    storage_path = tmp_path / 'assessment-file.txt'
    storage_path.write_text('Not a directory')

    with pytest.raises(
        ValueError,
        match='Storage path must be a directory.'
    ):
        validate_storage_directory(storage_path)


def test_validate_storage_directory_rejects_symbolic_link(tmp_path):
    '''
    Verify that a symbolic link pointing to a valid
    directory is rejected.
    '''

    # Create a real directory.
    actual_directory = tmp_path / 'actual-assessments'
    actual_directory.mkdir()

    # Create a symbolic link pointing to that directory.
    linked_directory = tmp_path / 'linked-assessments'
    linked_directory.symlink_to(
        actual_directory,
        target_is_directory=True
    )

    with pytest.raises(
        ValueError,
        match='Storage directory must not be a symbolic link.'
    ):
        validate_storage_directory(linked_directory)


def test_create_assessment_saves_and_loads_record(tmp_path):
    '''
    Verify that the assessment service creates a complete
    JSON record that can be loaded and reconstructed.
    '''

    # Create an isolated directory for this test.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create valid assessment metadata.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create the assessment through the service layer.
    saved_path = create_assessment(
        assessment,
        [],
        [],
        storage_directory
    )

    # Verify that the record was saved at the expected location.
    expected_path = storage_directory / 'ASM-2026-001.json'

    assert saved_path == expected_path
    assert saved_path.is_file()

    # Load the record through the existing storage layer.
    loaded_assessment, loaded_controls, loaded_findings = (
        load_assessment_record(saved_path)
    )

    # Verify that the reconstructed data matches the original.
    assert loaded_assessment == assessment
    assert loaded_controls == []
    assert loaded_findings == []

    # Verify that only the intended JSON file was created.
    assert list(storage_directory.iterdir()) == [expected_path]


def test_create_assessment_rejects_duplicate_id(tmp_path):
    '''
    Verify that creating an assessment with an existing ID
    does not overwrite the original assessment record.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create the original assessment.
    original_assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Original Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Save the original assessment through the service.
    original_path = create_assessment(
        original_assessment,
        [],
        [],
        storage_directory
    )

    # Capture the exact original file contents.
    original_contents = original_path.read_bytes()

    # Create a different assessment using the same ID.
    duplicate_assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Second Assessor',
        assessment_date=date(2026, 11, 2),
        framework='NIST CSF 2.0',
        scope='Third-Party Risk Management'
    )

    # Verify that the service refuses to overwrite the record.
    with pytest.raises(FileExistsError):
        create_assessment(
            duplicate_assessment,
            [],
            [],
            storage_directory
        )

    # Verify that the original file remains unchanged.
    assert original_path.read_bytes() == original_contents

    # Verify that the original assessment remains loadable.
    loaded_assessment, controls, findings = load_assessment_record(
        original_path
    )

    assert loaded_assessment == original_assessment
    assert controls == []
    assert findings == []

    # Verify that no additional files were created.
    assert list(storage_directory.iterdir()) == [original_path]


@pytest.mark.parametrize(
    'assessment_id',
    [
        '../secrets',
        '../../private',
        'ASM/2026/001',
        r'ASM\2026\001',
        'ASM.2026.001',
        'ASM 2026 001',
        '.hidden',
        'ASM-001.json'
    ],
)
def test_create_assessment_rejects_unsafe_identifiers(
    assessment_id,
    tmp_path
):
    '''
    Verify that unsafe assessment identifiers are rejected
    before the service creates any assessment files.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create valid assessment metadata with an identifier
    # that is permitted by the model but unsafe as a filename.
    assessment = Assessment(
        assessment_id=assessment_id,
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Verify that the service rejects the unsafe identifier.
    with pytest.raises(
        ValueError,
        match='assessment_id contains invalid filename characters',
    ):
        create_assessment(
            assessment,
            [],
            [],
            storage_directory
        )

    # Verify that no files were created.
    assert list(storage_directory.iterdir()) == []


@pytest.mark.parametrize(
    'invalid_directory_type, expected_error',
    [
        ('missing', 'Storage directory does not exist'),
        ('file', 'Storage path must be a directory'),
        ('symlink', 'Storage directory must not be a symbolic link')
    ]
)
def test_create_assessment_rejects_invalid_storage_directory(
    invalid_directory_type,
    expected_error,
    tmp_path
):
    '''
    Verify that assessment creation rejects invalid
    storage directories without writing any records.
    '''

    # Create valid assessment metadata.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Prepare the selected invalid storage location.
    storage_directory = tmp_path / 'assessments'

    if invalid_directory_type == 'file':
        # A regular file cannot serve as a storage directory.
        storage_directory.write_text('Not a directory')

    elif invalid_directory_type == 'symlink':
        # A symbolic link to a valid directory is still rejected.
        actual_directory = tmp_path / 'actual-assessments'
        actual_directory.mkdir()

        storage_directory.symlink_to(
            actual_directory,
            target_is_directory=True
        )

    # Attempt to create an assessment in the invalid location.
    with pytest.raises(ValueError, match=expected_error):
        create_assessment(
            assessment,
            [],
            [],
            storage_directory
        )

    # Verify that no assessment JSON files were created.
    assert list(tmp_path.rglob('*.json')) == []


def test_create_assessment_saves_populated_record(tmp_path):
    '''
    Verify that the assessment service saves and restores
    assessment metadata, control evaluations, and findings.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create assessment metadata.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a control evaluation belonging to the assessment.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='INSUFFICIENT',
        evidence_references=['EVID-001'],
        observations='Access reviews are performed inconsistently.'
    )

    # Create a finding associated with the assessed control.
    finding = Finding(
        finding_id='FIND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='Periodic access reviews are not consistently documented.',
        likelihood=3,
        impact=4,
        risk_rationale='Inappropriate access may remain undetected.',
        recommendation='Implement quarterly access reviews.'
    )

    # Save the complete assessment through the service layer.
    saved_path = create_assessment(
        assessment,
        [control],
        [finding],
        storage_directory
    )

    # Verify the expected destination.
    assert saved_path == storage_directory / 'ASM-2026-001.json'
    assert saved_path.is_file()

    # Load and reconstruct the saved assessment record.
    loaded_assessment, loaded_controls, loaded_findings = (
        load_assessment_record(saved_path)
    )

    # Verify all three model types were restored correctly.
    assert loaded_assessment == assessment
    assert loaded_controls == [control]
    assert loaded_findings == [finding]

    # Verify that the finding's calculated risk is preserved.
    assert loaded_findings[0].risk_score == 12
    assert loaded_findings[0].risk_severity == 'HIGH'

    # Verify that no unexpected files were created.
    assert list(storage_directory.iterdir()) == [saved_path]


def test_get_assessment_retrieves_existing_record(tmp_path):
    '''
    Verify that an assessment can be retrieved by its
    assessment_id through the service layer.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create valid assessment metadata.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Save the assessment through the creation service.
    create_assessment(
        assessment,
        [],
        [],
        storage_directory
    )

    # Retrieve the assessment using only its identifier.
    loaded_assessment, loaded_controls, loaded_findings = (
        get_assessment(
            'ASM-2026-001',
            storage_directory
        )
    )

    # Verify that the correct assessment was retrieved.
    assert loaded_assessment == assessment
    assert loaded_controls == []
    assert loaded_findings == []


def test_get_assessment_rejects_mismatched_assessment_id(tmp_path):
    '''
    Verify that retrieval rejects a record whose internal
    assessment_id differs from the requested identifier.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create valid assessment metadata.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Save a valid assessment record.
    saved_path = create_assessment(
        assessment,
        [],
        [],
        storage_directory
    )

    # Read the stored JSON record.
    record_data = json.loads(saved_path.read_text())

    # Change the internal assessment identifier while
    # leaving the filename unchanged.
    record_data['assessment']['assessment_id'] = 'ASM-2026-002'

    # Write the modified record to simulate a mismatched file.
    saved_path.write_text(json.dumps(record_data, indent=2))

    # Verify that the service detects the inconsistency.
    with pytest.raises(
        ValueError,
        match='Stored assessment_id does not match the requested assessment_id'
    ):
        get_assessment(
            'ASM-2026-001',
            storage_directory
        )


def test_get_assessment_rejects_nonexistent_record(tmp_path):
    '''
    Verify that retrieving a nonexistent assessment raises
    FileNotFoundError without modifying the storage directory.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Request an assessment that has not been saved.
    with pytest.raises(FileNotFoundError):
        get_assessment(
            'ASM-2026-999',
            storage_directory
        )

    # Verify that the failed lookup created no files.
    assert list(storage_directory.iterdir()) == []


@pytest.mark.parametrize(
    'assessment_id',
    [
        '../secrets',
        '../../private',
        'ASM/2026/001',
        r'ASM\2026\001',
        'ASM.2026.001',
        'ASM 2026 001',
        '.hidden',
        'ASM-001.json'
    ]
)
def test_get_assessment_rejects_unsafe_identifiers(
    assessment_id,
    tmp_path
):
    '''
    Verify that retrieval rejects unsafe assessment_id
    values before attempting to access assessment files.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Attempt retrieval using an unsafe identifier.
    with pytest.raises(
        ValueError,
        match='assessment_id contains invalid filename characters'
    ):
        get_assessment(
            assessment_id,
            storage_directory
        )

    # Verify that no files were created.
    assert list(storage_directory.iterdir()) == []


def test_get_assessment_rejects_malformed_json(tmp_path):
    '''
    Verify that retrieving an assessment containing malformed
    JSON raises JSONDecodeError without modifying the file.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create a file with the expected assessment filename.
    file_path = storage_directory / 'ASM-2026-001.json'

    # Write deliberately malformed JSON.
    invalid_contents = '{"schema_version": 1, "assessment":'

    file_path.write_text(invalid_contents, encoding='utf-8')

    # Verify that retrieval rejects the corrupted record.
    with pytest.raises(json.JSONDecodeError):
        get_assessment(
            'ASM-2026-001',
            storage_directory
        )

    # Verify that the original file remains unchanged.
    assert file_path.read_text(encoding='utf-8') == invalid_contents

    # Verify that no additional files were created.
    assert list(storage_directory.iterdir()) == [file_path]



@pytest.mark.parametrize(
    'invalid_record, expected_error',
    [
        (
            {
                'schema_version': 999,
                'assessment': {},
                'control_assessments': [],
                'findings': []
            },
            'Unsupported assessment record schema version'
        ),
        (
            {
                'schema_version': 1,
                'assessment': {},
                'control_assessments': []
            },
            'missing or unexpected sections'
        )
    ]
)
def test_get_assessment_rejects_invalid_record_structure(
    invalid_record,
    expected_error,
    tmp_path
):
    '''
    Verify that retrieval rejects syntactically valid JSON
    records that violate the assessment record schema.
    '''

    # Create an isolated private storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create the expected assessment file.
    file_path = storage_directory / 'ASM-2026-001.json'

    # Serialize the invalid record into valid JSON.
    original_contents = json.dumps(invalid_record, indent=2)

    file_path.write_text(
        original_contents,
        encoding='utf-8'
    )

    # Verify that the service rejects the invalid record.
    with pytest.raises(ValueError, match=expected_error):
        get_assessment(
            'ASM-2026-001',
            storage_directory
        )

    # Verify that retrieval did not modify the stored file.
    assert file_path.read_text(encoding='utf-8') == original_contents

    # Verify that no additional files were created.
    assert list(storage_directory.iterdir()) == [file_path]


def test_list_assessment_ids_filters_and_sorts_records(tmp_path):
    '''
    Verify that assessment listing returns sorted identifiers
    while ignoring invalid files, directories, and symbolic links.
    '''

    # Create an isolated assessment storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Create valid assessment files in an unsorted order.
    for assessment_id in [
        'ASM-2026-003',
        'ASM-2026-001',
        'ASM-2026-002'
    ]:
        (storage_directory / f'{assessment_id}.json').write_text(
            '{}',
            encoding='utf-8'
        )

    # Create a file with an invalid assessment identifier.
    (storage_directory / 'invalid.name.json').write_text(
        '{}',
        encoding='utf-8'
    )

    # Create an unrelated text file.
    (storage_directory / 'notes.txt').write_text(
        'Not an assessment record',
        encoding='utf-8'
    )

    # Create a directory whose name ends in .json.
    (storage_directory / 'DIRECTORY.json').mkdir()

    # Create a symbolic link pointing to a valid JSON file.
    (storage_directory / 'LINKED-001.json').symlink_to(
        storage_directory / 'ASM-2026-001.json'
    )

    # Retrieve assessment identifiers.
    assessment_ids = list_assessment_ids(storage_directory)

    # Verify that only valid regular JSON filenames are included.
    assert assessment_ids == [
        'ASM-2026-001',
        'ASM-2026-002',
        'ASM-2026-003'
    ]


def test_list_assessment_ids_returns_empty_list(tmp_path):
    '''
    Verify that listing an empty assessment directory
    returns an empty list without modifying the filesystem.
    '''

    # Create an isolated, empty assessment storage directory.
    storage_directory = tmp_path / 'assessments'
    storage_directory.mkdir()

    # Retrieve assessment identifiers.
    assessment_ids = list_assessment_ids(storage_directory)

    # Verify that no assessment identifiers were returned.
    assert assessment_ids == []

    # Verify that the directory remains empty.
    assert list(storage_directory.iterdir()) == []


@pytest.mark.parametrize(
    'invalid_directory_type, expected_error',
    [
        ('missing', 'Storage directory does not exist'),
        ('file', 'Storage path must be a directory'),
        ('symlink', 'Storage directory must not be a symbolic link'),
        ('string', 'Storage directory must be a Path object')
    ]
)
def test_list_assessment_ids_rejects_invalid_storage_directory(
    invalid_directory_type,
    expected_error,
    tmp_path
):
    '''
    Verify that assessment listing rejects invalid
    storage directory configurations.
    '''

    # Start with a nonexistent storage directory.
    storage_directory = tmp_path / 'assessments'

    if invalid_directory_type == 'file':
        # Create a regular file instead of a directory.
        storage_directory.write_text(
            'Not a directory',
            encoding='utf-8'
        )

    elif invalid_directory_type == 'symlink':
        # Create a symbolic link pointing to a real directory.
        actual_directory = tmp_path / 'actual-assessments'
        actual_directory.mkdir()

        storage_directory.symlink_to(
            actual_directory,
            target_is_directory=True
        )

    elif invalid_directory_type == 'string':
        # Supply an invalid argument type.
        storage_directory = str(storage_directory)

    # Verify that the invalid storage location is rejected.
    with pytest.raises(ValueError, match=expected_error):
        list_assessment_ids(storage_directory)

    # Verify that validation did not create assessment files.
    assert list(tmp_path.rglob('*.json')) == []
