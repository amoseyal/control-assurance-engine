import pytest
import json
import os

from datetime import date

from unittest.mock import patch

from src.assessment_models import (
    Assessment,
    ControlAssessment,
    Finding
)

from src.assessment_storage import(
    ASSESSMENT_RECORD_SCHEMA_VERSION,
    serialize_assessment,
    deserialize_assessment,
    serialize_control_assessment,
    deserialize_control_assessment,
    serialize_finding,
    deserialize_finding,
    save_assessment,
    load_assessment,
    serialize_assessment_record,
    deserialize_assessment_record,
    save_assessment_record,
    load_assessment_record,
    validate_assessment_record,
)


def test_serialize_assessment():
    '''
    Verify that an Assessment is converted into a
    JSON-compatible dictionary with an ISO 8601 date.
    '''

    # Create a valid cybersecurity assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Serialize the assessment.
    assessment_data = serialize_assessment(assessment)

    # Verify that the serialized fields retain their values.
    assert assessment_data == {
        'assessment_id': 'ASM-2026-001',
        'organization': 'Northstar BuildCo',
        'assessor': 'Test Assessor',
        'assessment_date': '2026-11-01',
        'framework': 'NIST CSF 2.0',
        'scope': 'Identity and Access Management'
    }


def test_assessment_serialization_round_trip():
    '''
    Verify that serializing and deserializing as
    Assessment preserves its original information.
    '''

    # Create the original, validated assessment.
    original_assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Convert the Assessment into a JSON-compatible dictionary.
    serialized_data = serialize_assessment(original_assessment)

    # Reconstruct the Assessment from the serialized dictionary.
    restored_assessment = deserialize_assessment(serialized_data)

    # Verify that the restored assessment matches the original.
    assert restored_assessment == original_assessment

    # Verify that the date was restored as a Python date object.
    assert serialized_data['assessment_date'] == '2026-11-01'


@pytest.mark.parametrize(
    'invalid_date',
    [
        'not-a-date',
        '2026-13-01',
        '2026-02-30',
        '',
        None,
        20261101
    ]
)
def test_deserialize_assessment_rejects_invalid_dates(
    invalid_date
):
    '''
    Verify that deserialization rejects malformed,
    nonexistent, and incorrectly typed assessment dates.
    '''

    # Start with a valid serialized assessment.
    assessment_data = {
        'assessment_id': 'ASM-2026-001',
        'organization': 'Northstar BuildCo',
        'assessor': 'Test Assessor',
        'assessment_date': '2026-11-01',
        'framework': 'NIST CSF 2.0',
        'scope': 'Identity and Access Management'
    }

    # Replace the valid date with an invalid value.
    assessment_data['assessment_date'] = invalid_date

    # Verify that the invalid date is rejected.
    with pytest.raises(ValueError, match='assessment_date'):
        deserialize_assessment(assessment_data)



@pytest.mark.parametrize(
    'field_name',
    [
        'assessment_id',
        'organization',
        'assessor',
        'assessment_date',
        'framework',
        'scope'
    ]
)
def test_deserialize_assessment_rejects_missing_fields(
    field_name,
):
    '''
    Verify that deserialization rejects assessment
    records with missing required fields.
    '''

    # Create a valid serialized assessment.
    assessment_data = {
        'assessment_id': 'ASM-2026-001',
        'organization': 'Northstar BuildCo',
        'assessor': 'Test Assessor',
        'assessment_date': '2026-11-01',
        'framework': 'NIST CSF 2.0',
        'scope': 'Identity and Access Management'
    }

    # Remove one required field.
    del assessment_data[field_name]

    # Verify that reconstruction fails.
    with pytest.raises((TypeError, ValueError)):
        deserialize_assessment(assessment_data)


def test_deserialize_assessment_rejects_unexpected_fields():
    '''
    Verify that deserialization rejects fields
    not defined by the Assessment model.
    '''

    assessment_data = {
        'assessment_id': 'ASM-2026-001',
        'organization': 'Northstar BuildCo',
        'assessor': 'Test Assessor',
        'assessment_date': '2026-11-01',
        'framework': 'NIST CSF 2.0',
        'scope': 'Identity and Access Management',
        'unauthorized_field': 'unexpected value'
    }

    # The Assessment constructor must reject unknown fields.
    with pytest.raises(TypeError):
        deserialize_assessment(assessment_data)


def test_serialize_control_assessment():
    '''
    Verify that ControlAssessment serialization preserves
    all fields and converts evidence references to a list.
    '''

    # Create a validated control assessment.
    control_assessment = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001', 'EVID-002'],
        observations='MFA is not enforced for all users.'
    )

    # Serialize the control assessment.
    control_data = serialize_control_assessment(
        control_assessment
    )

    # VErify that every field is preserved.
    assert control_data == {
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'assessment_method': 'MANUAL',
        'implementation_status': 'PARTIALLY_IMPLEMENTED',
        'evidence_status': 'SUFFICIENT',
        'evidence_references': ['EVID-001', 'EVID-002'],
        'observations': 'MFA is not enforced for all users.'
    }

    # Verify that serialized evidence references are a list.
    assert isinstance(control_data['evidence_references'], list)

    # Verify that the original model retains its immutable tuple.
    assert control_assessment.evidence_references == (
        'EVID-001',
        'EVID-002'
    )


def test_control_assessemnt_serialization_round_trip():
    '''
    Verify that serializing and deserializing a
    ControlAssessment preserves its original information.
    '''

    # Create an original, validated control assessment.
    original_control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001', 'EVID-002'],
        observations='MFA is not enforced for all users.'
    )

    # Convert the control assessment into a dictionary.
    serialized_data = serialize_control_assessment(
        original_control
    )

    # Reconstruct the control assessment.
    restored_control = deserialize_control_assessment(
        serialized_data
    )

    # Verify that evidence references are restored as a tuple.
    assert isinstance(restored_control.evidence_references, tuple)

    # Verify that deserialization preserves the input dictionary.
    assert serialized_data['evidence_references'] == [
        'EVID-001',
        'EVID-002'
    ]


@pytest.mark.parametrize(
    'invalid_references',
    [
        None,
        'EVID-001',
        123,
        {'id': 'EVID-001'},
        ['EVID-001', ''],
        ['EVID-001', None],
        ['EVID-001', 123]
    ]
)
def test_deserialize_control_assessment_rejects_invalid_evidence(
    invalid_references,
):
    '''
    Verify that deserialization rejects malformed
    evidence references.
    '''

    # Create a valid serialized control assessment.
    control_data = {
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'assessment_method': 'MANUAL',
        'implementation_status': 'PARTIALLY_IMPLEMENTED',
        'evidence_status': 'SUFFICIENT',
        'evidence_references': ['EVID-001'],
        'observations': 'MFA is not enforced for all users.',
    }

    # Replace the valid evidence references with invalid data.
    control_data['evidence_references'] = invalid_references

    # Verify that the model rejects the invalid evidence.
    with pytest.raises((TypeError, ValueError)):
        deserialize_control_assessment(control_data)


def test_serialize_finding():
    '''
     Verify that Finding serialization preserves all
    stored fields and excludes calculated risk properties.
    '''

    # Create a validated finding.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    # Serialize the finding.
    finding_data = serialize_finding(finding)

    # Verify that every stored field is preserved.
    assert finding_data == {
        'finding_id': 'FND-001',
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'description': 'MFA is not enforced for all users.',
        'likelihood': 4,
        'impact': 5,
        'risk_rationale': 'Unauthorized access could expose sensitive data.',
        'recommendation': 'Enforce MFA for all user accounts.'
    }

    # Verify that calsulated properties are not stored.
    assert 'risk_score' not in finding_data
    assert 'risk_severity' not in finding_data

    # Verify that the original model calculates risk correctly.
    assert finding.risk_score == 20
    assert finding.risk_severity == 'CRITICAL'


def test_finding_serialization_round_trip():
    '''
    Verify that serializing and deserializing a Finding
    preserves its information and calculated risk values.
    '''

    # Create an original, validated finding.
    original_finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.',
    )

    # Convert the Finding into a JSON-compatible dictionary.
    serialized_data = serialize_finding(original_finding)

    # Reconstruct the Finding from the serialized dictionary.
    restored_finding = deserialize_finding(serialized_data)

    # Verify that the restored finding matches the original.
    assert restored_finding == original_finding

    # Verify that calculated risk properties remain correct.
    assert restored_finding.risk_score == 20
    assert restored_finding.risk_severity == 'CRITICAL'

    # Verify that calculated properties were not persisted.
    assert 'risk_score' not in serialized_data
    assert 'risk_severity' not in serialized_data


@pytest.mark.parametrize(
    'field_name, invalid_value',
    [
        ('likelihood', 0),
        ('likelihood', 6),
        ('likelihood', 2.5),
        ('likelihood', '4'),
        ('likelihood', True),
        ('impact', 0),
        ('impact', 6),
        ('impact', 2.5),
        ('impact', '5'),
        ('impact', False),
    ],
)
def test_deserialize_finding_rejects_invalid_risk_values(
    field_name,
    invalid_value,
):
    '''
    Verify that deserialization rejects invalid likelihood
    and impact values, including booleans and non-integers.
    '''

    # Create a valid serialized finding.
    finding_data = {
        'finding_id': 'FND-001',
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'description': 'MFA is not enforced for all users.',
        'likelihood': 4,
        'impact': 5,
        'risk_rationale': 'Unauthorized access could expose sensitive data.',
        'recommendation': 'Enforce MFA for all user accounts.',
    }

    # Replace one valid risk value with an invalid value.
    finding_data[field_name] = invalid_value

    # Verify that the Finding model rejects the invalid value.
    with pytest.raises((TypeError, ValueError)):
        deserialize_finding(finding_data)


def test_save_assessment(tmp_path):
    '''
    Verify that a validated Assessment is saved
    correctly as a JSON file.
    '''

    # Create a validated assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Create a temporary file path for the assessment.
    file_path = tmp_path / 'assessment.json'

    # Save the assessment to the temporary JSON file.
    save_assessment(assessment, file_path)

    # Verify that the file was created.
    assert file_path.is_file()

    # Read the saved JSON file.
    with file_path.open('r', encoding='utf-8') as file:
        saved_data = json.load(file)

    # Verify that the saved data matches the assessment.
    assert saved_data == serialize_assessment(assessment)

    # Verify that the date was stored as an ISO 8601 string.
    assert saved_data['assessment_date'] == '2026-11-01'


def test_assessment_file_round_trip(tmp_path):
    '''
    Verify that saving and loading an Assessment
    preserves its original information.
    '''

    # Create an original, validated assessment.
    original_assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Define a temporary JSON file path.
    file_path = tmp_path / 'assessment.json'

    # Save the assessment to disk.
    save_assessment(original_assessment, file_path)

    # Load and reconstruct the assessment from disk.
    restored_assessment = load_assessment(file_path)

    # Verify that the restored assessment matches the original.
    assert restored_assessment == original_assessment

    # Verify that the date is restored as a Python date object.
    assert type(restored_assessment.assessment_date) is date

    # Verify that the restored assessment remains immutable.
    assert restored_assessment is not original_assessment


def test_load_assessment_rejects_missing_file(tmp_path):
    '''
    Verify that loading a nonexistent assessment
    file raises FileNotFoundError.
    '''

    # Define a path to a file that does not exist.
    file_path = tmp_path / 'nonexistent_assessment.json'

    # Confirm that the file does not exist.
    assert not file_path.exists()

    # Verify that loading the missing file raises an error.
    with pytest.raises(FileNotFoundError):
        load_assessment(file_path)


def test_load_assessemnt_rejects_malformed_json(tmp_path):
    '''
    Verify that loading a file containing malformed
    JSON raises json.JSONDecodeError.
    '''

    # Define a temporary JSON file path.
    file_path = tmp_path / 'malformed_assessment.json'

    # Write deliberately malformed JSON to the file.
    file_path.write_text(
        '{"assessment_id": "ASK-2026-001",',
        encoding='utf-8'
    )

    # Verify that loading the malformed file raises an error.
    with pytest.raises(json.JSONDecodeError):
        load_assessment(file_path)


def test_save_assessment_rejects_existing_file(tmp_path):
    '''
    Verify that saving an assessment cannot overwrite
    an existing file or modify its contents.
    '''

    # Create a validated assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Define a temporary JSON file path.
    file_path = tmp_path / 'assessment.json'

    # Create an existing file containing original data.
    original_content = '{"existing": "important data"}'
    file_path.write_text(original_content, encoding='utf-8')

    # Verify that saving to the existing path is rejected.
    with pytest.raises(FileExistsError):
        save_assessment(assessment, file_path)

    # Verify that the existing file remains unchanged.
    assert file_path.read_text(encoding='utf-8') == original_content


def test_save_assessment_serialization_failure_creates_no_file(
    tmp_path,
    monkeypatch,
):
    '''
    Verify that a JSON serialization failure does not
    create an incomplete assessment file.
    '''

    # Create a validated assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Define the destination file path.
    file_path = tmp_path / 'assessment.json'

    # Simulate a JSON serialization failure.
    def failing_json_dumps(*args, **kwargs):
        raise TypeError('Simulated JSON serialization failure.')

    monkeypatch.setattr(
        'src.assessment_storage.json.dumps',
        failing_json_dumps,
    )

    # Verify that the serialization error propagates.
    with pytest.raises(TypeError, match='Simulated JSON'):
        save_assessment(assessment, file_path)

    # Verify that no incomplete file was created.
    assert not file_path.exists()


def test_save_assessment_write_failure_cleans_up(
    tmp_path,
    monkeypatch,
):
    '''
    Verify that a failed temporary-file write
    leaves no destination or temporary files.
    '''

    # Create a validated assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Define the intended destination.
    file_path = tmp_path / 'assessment.json'

    # Replace os.fsync() with a simulated disk synchronization failure.
    def failing_fsync(file_descriptor):
        raise OSError('Simulated disk synchronization failure.')

    monkeypatch.setattr(
        'src.assessment_storage.os.fsync',
        failing_fsync,
    )

    # Verify that the failure propagates.
    with pytest.raises(OSError, match='Simulated disk'):
        save_assessment(assessment, file_path)

    # Verify that no incomplete assessment was published.
    assert not file_path.exists()

    # Verify that the temporary file was removed.
    assert list(tmp_path.iterdir()) == []


def test_save_assessment_publication_failure_cleans_up(
    tmp_path,
    monkeypatch,
):
    '''
    Verify that a failed atomic publication leaves
    no destination file or orphaned temporary file.
    '''

    # Create a validated assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Define the intended destination.
    file_path = tmp_path / 'assessment.json'

    # Simulate a failure during atomic publication.
    def failing_link(source, destination):
        raise OSError('Simulated atomic publication failure.')

    monkeypatch.setattr(
        'src.assessment_storage.os.link',
        failing_link,
    )

    # Verify that the publication error propagates.
    with pytest.raises(OSError, match='Simulated atomic publication'):
        save_assessment(assessment, file_path)

    # Verify that no assessment was published.
    assert not file_path.exists()

    # Verify that the temporary file was removed.
    assert list(tmp_path.iterdir()) == []


def test_save_assessment_publication_conflict_preserves_file(
    tmp_path,
):
    '''
    Verify that atomic publication cannot overwrite
    an existing assessment and cleans up temporary files.
    '''

    # Create a validated assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management',
    )

    # Define the destination path.
    file_path = tmp_path / 'assessment.json'

    # Create an existing file containing important data.
    original_content = '{"existing": "important data"}'
    file_path.write_text(original_content, encoding='utf-8')

    # Verify that atomic publication rejects the existing path.
    with pytest.raises(FileExistsError):
        save_assessment(assessment, file_path)

    # Verify that the original contents remain unchanged.
    assert file_path.read_text(encoding='utf-8') == original_content

    # Verify that no temporary files remain.
    assert list(tmp_path.iterdir()) == [file_path]


def test_serialize_assessment_record():
    '''
    Verify that a complete assessment record contains
    correctly serialized metadata, controls, and findings.
    '''

    # Create validated assessment metadata.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a validated control evaluation.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is not enforced for all users.'
    )

    # Create a validated risk finding.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    # Serialize the complete assessment record.
    record = serialize_assessment_record(
        assessment,
        [control],
        [finding]
    )

    # Verify the record contains the expected sections.
    assert set(record) == {
        'schema_version',
        'assessment',
        'control_assessments',
        'findings'
    }

    # Verify that the record uses the supported schema version.
    assert record['schema_version'] == ASSESSMENT_RECORD_SCHEMA_VERSION

    # Verify each section matches its individual serialization.
    assert record['assessment'] == serialize_assessment(assessment)

    assert record['control_assessments'] == [
        serialize_control_assessment(control)
    ]

    assert record['findings'] == [
        serialize_finding(finding)
    ]

    # Verify the entire record can be encoded as JSON.
    json.dumps(record)


@pytest.mark.parametrize(
    'mismatched_record',
    [
        'control',
        'finding'
    ],
)
def test_serialize_assessment_record_rejects_mismatched_ids(
    mismatched_record
):
    '''
    Verify that controls and findings referencing a
    different assessment ID are rejected.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a control evaluation.
    control = ControlAssessment(
        assessment_id=(
            'ASM-2026-002'
            if mismatched_record == 'control'
            else 'ASM-2026-001'
        ),
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is not enforced for all users.'
    )

    # Create a risk finding.
    finding = Finding(
        finding_id='FND-001',
        assessment_id=(
            'ASM-2026-002'
            if mismatched_record == 'finding'
            else 'ASM-2026-001'
        ),
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    # Verify that inconsistent assessment IDs are rejected.
    with pytest.raises(ValueError, match='different assessment'):
        serialize_assessment_record(
            assessment,
            [control],
            [finding]
        )


def test_serialize_assessment_record_rejects_unassessed_control():
    '''
    Verify that a finding cannot reference a control
    absent from the assessment's control evaluations.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create an evaluation for control IAM-01.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is not enforced for all users.'
    )

    # Create a finding referencing a different control.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='END-01',
        description='Endpoint protection is not consistently deployed.',
        likelihood=4,
        impact=4,
        risk_rationale='Unprotected endpoints increase compromise risk.',
        recommendation='Deploy endpoint protection to all devices.'
    )

    # Verify that the unassessed control reference is rejected.
    with pytest.raises(ValueError, match='unassessed control'):
        serialize_assessment_record(
            assessment,
            [control],
            [finding]
        )


def test_serialize_assessment_record_rejects_duplicate_controls():
    '''
    Verify that an assessment record cannot contain
    multiple evaluations of the same control.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create the first evaluation of IAM-01.
    control_1 = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is enforced for all users.'
    )

    # Create a conflicting evaluation of the same control.
    control_2 = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='INSUFFICIENT',
        evidence_references=['EVID-002'],
        observations='MFA coverage could not be fully verified.'
    )

    # Verify that duplicate control identifiers are rejected.
    with pytest.raises(
        ValueError,
        match='Duplicate control identifiers'
        ):
        serialize_assessment_record(
            assessment,
            [control_1, control_2],
            []
        )


def test_serialize_assessment_record_rejects_duplicate_findings():
    '''
    Verify that an assessment record cannot contain
    multiple findings with the same identifier.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create an evaluated control.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is not enforced for all users.'
    )

    # Create the first finding.
    finding_1 = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

     # Create a second finding with the same identifier.
    finding_2 = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='Privileged accounts lack additional monitoring.',
        likelihood=3,
        impact=4,
        risk_rationale='Privileged account misuse may go undetected.',
        recommendation='Implement privileged account monitoring.'
    )

    # Verify that duplicate finding identifiers are rejected.
    with pytest.raises(
        ValueError,
        match='Duplicate finding identifiers'
        ):
        serialize_assessment_record(
            assessment,
            [control],
            [finding_1, finding_2]
        )


def test_serialize_assessment_record_allows_multiple_findings_per_control():
    '''
    Verify that multiple findings with unique identifiers
    can reference the same assessed control.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create one evaluated control.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='Several IAM weaknesses were identified.'
    )

    # Create two distinct findings for the same control.
    finding_1 = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    finding_2 = Finding(
        finding_id='FND-002',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='Privileged accounts lack additional monitoring.',
        likelihood=3,
        impact=4,
        risk_rationale='Privileged account misuse may go undetected.',
        recommendation='Implement privileged account monitoring.'
    )

     # Serialize the assessment with both findings.
    record = serialize_assessment_record(
        assessment,
        [control],
        [finding_1, finding_2],
    )

    # Verify that both findings are preserved.
    assert len(record['findings']) == 2

    # Verify that the finding identifiers remain unique.
    assert {
        finding['finding_id']
        for finding in record['findings']
    } == {'FND-001', 'FND-002'}

    # Verify that both findings reference the same control.
    assert all(
        finding['control_id'] == 'IAM-01'
        for finding in record['findings']
    )


def test_assessment_record_serialization_round_trip():
    '''
    Verify that a complete assessment record can be
    serialized and reconstructed without losing data.
    '''

    # create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a control evaluation.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is not enforced for all users.'
    )

    # Create a risk finding.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    # Serialize the complete record.
    serialized_record = serialize_assessment_record(
        assessment,
        [control],
        [finding],
    )

    # Reconstruct the validated models.
    restored_assessment, restored_controls, restored_findings = (
        deserialize_assessment_record(serialized_record)
    )

    # Verify that all reconstructed models match the originals.
    assert restored_assessment == assessment
    assert restored_controls == [control]
    assert restored_findings == [finding]

    # Verify that the restored evidence references are immutable.
    assert restored_controls[0].evidence_references == ('EVID-001',)

    # Verify that calculated risk properties remain correct.
    assert restored_findings[0].risk_score == 20
    assert restored_findings[0].risk_severity == 'CRITICAL'

    # Verify that the original serialized data remains unchanged.
    assert serialized_record['assessment']['assessment_date'] == (
        '2026-11-01'
    )
    assert serialized_record['control_assessments'][0][
        'evidence_references'
    ] == ['EVID-001']


@pytest.mark.parametrize(
    'mismatched_section',
    [
        'control_assessments',
        'findings',
    ],
)
def test_deserialize_assessment_record_rejects_mismatched_ids(
    mismatched_section,
):
    '''
    Verify that complete-record deserialization rejects
    controls or findings belonging to another assessment.
    '''

    # Create a valid serialized assessment record.
    record_data = {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': {
            'assessment_id': 'ASM-2026-001',
            'organization': 'Northstar BuildCo',
            'assessor': 'Test Assessor',
            'assessment_date': '2026-11-01',
            'framework': 'NIST CSF 2.0',
            'scope': 'Identity and Access Management',
        },
        'control_assessments': [
            {
                'assessment_id': 'ASM-2026-001',
                'control_id': 'IAM-01',
                'assessment_method': 'MANUAL',
                'implementation_status': 'PARTIALLY_IMPLEMENTED',
                'evidence_status': 'SUFFICIENT',
                'evidence_references': ['EVID-001'],
                'observations': 'MFA is not enforced for all users.',
            },
        ],
        'findings': [
            {
                'finding_id': 'FND-001',
                'assessment_id': 'ASM-2026-001',
                'control_id': 'IAM-01',
                'description': 'MFA is not enforced for all users.',
                'likelihood': 4,
                'impact': 5,
                'risk_rationale': 'Unauthorized access could expose sensitive data.',
                'recommendation': 'Enforce MFA for all user accounts.',
            },
        ],
    }

    # Introduce an inconsistent assessment ID.
    record_data[mismatched_section][0]['assessment_id'] = (
        'ASM-2026-002'
    )

    # Verify that the invalid relationship is rejected.
    with pytest.raises(ValueError, match='different assessment'):
        deserialize_assessment_record(record_data)



def test_deserialize_assessment_record_rejects_unassessed_control():
    '''
    Verify that deserialization rejects a finding
    referencing a control absent from the assessment.
    '''

    # Create a valid serialized assessment record.
    record_data = {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': {
            'assessment_id': 'ASM-2026-001',
            'organization': 'Northstar BuildCo',
            'assessor': 'Test Assessor',
            'assessment_date': '2026-11-01',
            'framework': 'NIST CSF 2.0',
            'scope': 'Identity and Access Management'
        },
        'control_assessments': [
            {
                'assessment_id': 'ASM-2026-001',
                'control_id': 'IAM-01',
                'assessment_method': 'MANUAL',
                'implementation_status': 'PARTIALLY_IMPLEMENTED',
                'evidence_status': 'SUFFICIENT',
                'evidence_references': ['EVID-001'],
                'observations': 'MFA is not enforced for all users.'
            }
        ],
        'findings': [
            {
                'finding_id': 'FND-001',
                'assessment_id': 'ASM-2026-001',
                'control_id': 'END-01',
                'description': 'Endpoint protection is not consistently deployed.',
                'likelihood': 4,
                'impact': 4,
                'risk_rationale': 'Unprotected endpoints increase compromise risk.',
                'recommendation': 'Deploy endpoint protection to all devices.'
            }
        ],
    }

    # Verify that the invalid control reference is rejected.
    with pytest.raises(ValueError, match='unassessed control'):
        deserialize_assessment_record(record_data)


def test_deserialize_assessment_record_rejects_duplicate_controls():
    '''
    Verify that deserialization rejects multiple
    evaluations of the same control.
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

    # Create two evaluations with the same control ID.
    control_1 = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is enforced for all users.'
    )

    control_2 = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='INSUFFICIENT',
        evidence_references=['EVID-002'],
        observations='MFA coverage could not be fully verified.'
    )

    # Construct a stored record directly to bypass
    # serialization-level referential-integrity checks.
    record_data = {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': serialize_assessment(assessment),
        'control_assessments': [
            serialize_control_assessment(control_1),
            serialize_control_assessment(control_2)
        ],
        'findings': []
    }

    # Verify that duplicate controls are rejected on loading.
    with pytest.raises(ValueError, match='Duplicate control identifiers'):
        deserialize_assessment_record(record_data)


def test_deserialize_assessment_record_rejects_duplicate_findings():
    '''
    Verify that deserialization rejects multiple findings
    with the same finding identifier.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create the assessed control referenced by both findings.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA implementation requires improvement.'
    )

    # Create two findings with the same finding ID.
    finding_1 = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Accounts are exposed to unauthorized access.',
        recommendation='Enforce MFA for all users.'
    )

    finding_2 = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA enrollment is not regularly reviewed.',
        likelihood=3,
        impact=4,
        risk_rationale='Inactive MFA registrations may remain undetected.',
        recommendation='Perform periodic MFA enrollment reviews.'
    )

    # Construct the stored record directly, bypassing
    # complete-record serialization validation.
    record_data = {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': serialize_assessment(assessment),
        'control_assessments': [
            serialize_control_assessment(control),
        ],
        'findings': [
            serialize_finding(finding_1),
            serialize_finding(finding_2)
        ]
    }

    # Verify that duplicate finding identifiers are rejected.
    with pytest.raises(ValueError, match='Duplicate finding identifiers'):
        deserialize_assessment_record(record_data)


def test_save_assessment_record_creates_complete_json_file(tmp_path):
    '''
    Verify that a complete assessment record is saved
    as valid JSON with all expected components.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create an evaluated control.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is not enforced for all users.'
    )

    # Create a finding associated with the control.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    # Save the complete assessment to a temporary test directory.
    file_path = tmp_path / 'assessment-record.json'

    save_assessment_record(
        assessment,
        [control],
        [finding],
        file_path
    )

    # Verify that the file was created.
    assert file_path.is_file()

    # Read the saved JSON document.
    with file_path.open('r', encoding='utf-8') as file:
        saved_data = json.load(file)

    # Verify the complete record matches the expected serialization.
    assert saved_data == serialize_assessment_record(
        assessment,
        [control],
        [finding]
    )

    # Verify that the saved record can be reconstructed.
    restored_assessment, restored_controls, restored_findings = (
        deserialize_assessment_record(saved_data)
    )

    assert restored_assessment == assessment
    assert restored_controls == [control]
    assert restored_findings == [finding]


def test_save_assessment_record_rejects_existing_file(tmp_path):
    '''
    Verify that saving a complete assessment record
    cannot overwrite an existing file.
    '''

    # Create a valid assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a destination file containing existing data.
    file_path = tmp_path / 'assessment-record.json'
    original_content = '{"existing": "protected"}'
    file_path.write_text(original_content, encoding='utf-8')

    # Attempt to save a complete assessment to the same path.
    with pytest.raises(FileExistsError):
        save_assessment_record(
            assessment,
            [],
            [],
            file_path
        )

    # Verify that the original file remains unchanged.
    assert file_path.read_text(encoding='utf-8') == original_content

    # Verify that the failed operation left no temporary files.
    assert sorted(tmp_path.iterdir()) == [file_path]


def test_save_assessment_record_rejects_invalid_relationships(tmp_path):
    '''
    Verify that an invalid finding-to-control relationship
    prevents file creation and leaves no temporary files.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a valid control evaluation.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is enforced for all users.'
    )

    # Create a finding that references a different,
    # unassessed control.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='END-01',
        description='Endpoint protection is missing.',
        likelihood=4,
        impact=4,
        risk_rationale='Unprotected devices increase compromise risk.',
        recommendation='Deploy endpoint protection to all devices.'
    )

    # Define the intended output path.
    file_path = tmp_path / 'assessment-record.json'

    # Verify that the invalid relationship is rejected.
    with pytest.raises(ValueError, match='unassessed control'):
        save_assessment_record(
            assessment,
            [control],
            [finding],
            file_path
        )

    # Verify that no destination file was created.
    assert not file_path.exists()

    # Verify that no temporary files were created.
    assert list(tmp_path.iterdir()) == []


def test_save_and_load_complete_assessment_record(tmp_path):
    '''
    Verify that saving and loading a complete assessment
    preserves its metadata, control evaluations, and findings.
    '''

    # Create the parent assessment.
    assessment = Assessment(
            assessment_id='ASM-2026-001',
            organization='Northstar BuildCo',
            assessor='Test Assessor',
            assessment_date=date(2026, 11, 1),
            framework='NIST CSF 2.0',
            scope='Identity and Access Management'
    )

    # Create a control evaluation with supporting evidence.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method='HYBRID',
            implementation_status='PARTIALLY_IMPLEMENTED',
            evidence_status='SUFFICIENT',
            evidence_references=['EVID-001', 'EVID-002'],
            observations='MFA coverage requires improvement.'
    )

    # Create a finding associated with the evaluated control.
    finding = Finding(
        finding_id='FND-001',
            assessment_id='ASM-2026-001',
            control_id='IAM-01',
            description='MFA is not enforced for all users.',
            likelihood=4,
            impact=5,
            risk_rationale='Unauthorized access could expose sensitive data.',
            recommendation='Enforce MFA for all user accounts.'
    )

    # Define the destination file in pytest's temporary directory.
    file_path = tmp_path / 'assessment-record.json'

    # Save the complete assessment record to disk.
    save_assessment_record(
        assessment,
        [control],
        [finding],
        file_path
    )

    # Load the complete record from the saved JSON file.
    restored_assessment, restored_controls, restored_findings = (
        load_assessment_record(file_path)
    )

    # Verify that the restored objects match the originals.
    assert restored_assessment == assessment
    assert restored_controls == [control]
    assert restored_findings == [finding]

    # Verify that the date was reconstructed as a Python date.
    assert restored_assessment.assessment_date == date(2026, 11, 1)

    # Verify that evidence references remain immutable.
    assert restored_controls[0].evidence_references == (
        'EVID-001',
        'EVID-002'
    )

    # Verify that calculated risk properties remain available.
    assert restored_findings[0].risk_score == 20
    assert restored_findings[0].risk_severity == 'CRITICAL'


def test_load_assessment_record_rejects_missing_file(tmp_path):
    '''
    Verify that loading a nonexistent assessment record
    raises FileNotFoundError without creating any files.
    '''

    # Define a path that does not exist.
    file_path = tmp_path / 'missing-assessment.json'

    # Confirm the file is absent before attempting to load it.
    assert not file_path.exists()

    # Verify that loading the missing file raises the
    # expected filesystem exception.
    with pytest.raises(FileNotFoundError):
        load_assessment_record(file_path)

    # Verify that the failed load did not create any files.
    assert list(tmp_path.iterdir()) == []


def test_load_assessment_record_rejects_malformed_json(tmp_path):
    '''
    Verify that loading a file containing malformed JSON
    raises JSONDecodeError without modifying the file.
    '''

    # Create a file containing deliberately invalid JSON.
    file_path = tmp_path / 'malformed-assessment.json'
    invalid_content = '{"assessment": invalid JSON}'

    file_path.write_text(
        invalid_content,
        encoding='utf-8'
    )

    # Verify that the JSON parser rejects the malformed file.
    with pytest.raises(json.JSONDecodeError):
        load_assessment_record(file_path)

    # Verify that loading did not alter the original file.
    assert file_path.read_text(
        encoding='utf-8'
    ) == invalid_content

    # Verify that no additional files were created.
    assert sorted(tmp_path.iterdir()) == [file_path]


def test_load_assessment_record_rejects_invalid_assessment_data(tmp_path):
    '''
    Verify that loading syntactically valid JSON with an
    invalid assessment date raises a validation error.
    '''

    # Construct a complete record with an invalid date.
    record_data = {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': {
            'assessment_id': 'ASM-2026-001',
            'organization': 'Northstar BuildCo',
            'assessor': 'Test Assessor',
            'assessment_date': '2026-13-01',
            'framework': 'NIST CSF 2.0',
            'scope': 'Identity and Access Management'
        },
        'control_assessments': [],
        'findings': []
    }

    # Save the invalid record as syntactically valid JSON.
    file_path = tmp_path / 'invalid-assessment.json'
    original_content = json.dumps(record_data, indent=2)

    file_path.write_text(
        original_content,
        encoding='utf-8'
    )

    # Verify that model reconstruction rejects the date.
    with pytest.raises(ValueError, match='assessment_date'):
        load_assessment_record(file_path)

    # Verify that the invalid source file remains unchanged.
    assert file_path.read_text(
        encoding='utf-8',
    ) == original_content

    # Verify that loading created no additional files.
    assert sorted(tmp_path.iterdir()) == [file_path]


def test_load_assessment_record_rejects_invalid_control_reference(tmp_path):
    '''
    Verify that loading a stored assessment rejects a
    finding referencing a control that was not assessed.
    '''

    # Construct a complete assessment record with an
    # invalid finding-to-control relationship.
    record_data = {
        'schema_version': ASSESSMENT_RECORD_SCHEMA_VERSION,
        'assessment': {
            'assessment_id': 'ASM-2026-001',
            'organization': 'Northstar BuildCo',
            'assessor': 'Test Assessor',
            'assessment_date': '2026-11-01',
            'framework': 'NIST CSF 2.0',
            'scope': 'Identity and Access Management'
        },
        'control_assessments': [
            {
                'assessment_id': 'ASM-2026-001',
                'control_id': 'IAM-01',
                'assessment_method': 'MANUAL',
                'implementation_status': 'IMPLEMENTED',
                'evidence_status': 'SUFFICIENT',
                'evidence_references': ['EVID-001'],
                'observations': 'MFA is enforced for all users.'
            }
        ],
        'findings': [
            {
                'finding_id': 'FND-001',
                'assessment_id': 'ASM-2026-001',
                'control_id': 'END-01',
                'description': 'Endpoint protection is missing.',
                'likelihood': 4,
                'impact': 4,
                'risk_rationale': 'Unprotected devices increase compromise risk.',
                'recommendation': 'Deploy endpoint protection to all devices.'
            }
        ]
    }

    # Write the invalid record directly to disk,
    # bypassing the validated save function.
    file_path = tmp_path / 'invalid-control-reference.json'
    original_content = json.dumps(record_data, indent=2)

    file_path.write_text(
        original_content,
        encoding='utf-8'
    )

    # Verify that loading rejects the invalid relationship.
    with pytest.raises(ValueError, match='unassessed control'):
        load_assessment_record(file_path)

    # Verify that the original file remains unchanged.
    assert file_path.read_text(
        encoding='utf-8'
    ) == original_content

    # Verify that no additional files were created.
    assert sorted(tmp_path.iterdir()) == [file_path]


def test_validate_assessment_record_accepts_valid_relationships():
    '''
    Verify that the validator accepts a complete assessment
    with multiple distinct findings for the same control.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create an evaluated control belonging to the assessment.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='HYBRID',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA implementation requires improvement.'
    )

    # Create two distinct findings associated with the same control.
    finding_1 = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all users.'
    )

    finding_2 = Finding(
        finding_id='FND-002',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA enrollment is not periodically reviewed.',
        likelihood=3,
        impact=4,
        risk_rationale='Inactive registrations may remain undetected.',
        recommendation='Conduct periodic MFA enrollment reviews.'
    )

    # A valid record should pass without raising an exception.
    result = validate_assessment_record(
        assessment,
        [control],
        [finding_1, finding_2]
    )

    # The validator performs checks without returning data.
    assert result is None


@pytest.mark.parametrize(
    'invalid_record_type',
    [
        'control',
        'finding'
    ]
)
def test_validate_assessment_record_rejects_mismatched_assessment_ids(
    invalid_record_type,
):
    '''
    Verify that the validator rejects controls and findings
    belonging to a different parent assessment.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create a control evaluation.
    control = ControlAssessment(
        assessment_id=(
            'ASM-2026-002'
            if invalid_record_type == 'control'
            else 'ASM-2026-001'
        ),
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is enforced for all users.'
    )

    # Create a finding associated with the evaluated control.
    finding = Finding(
        finding_id='FND-001',
        assessment_id=(
            'ASM-2026-002'
            if invalid_record_type == 'finding'
            else 'ASM-2026-001'
        ),
        control_id='IAM-01',
        description='MFA enrollment requires periodic review.',
        likelihood=3,
        impact=4,
        risk_rationale='Inactive registrations may remain undetected.',
        recommendation='Conduct periodic MFA enrollment reviews.'
    )

    # Verify that the mismatched assessment ID is rejected.
    with pytest.raises(ValueError, match='different assessment'):
        validate_assessment_record(
            assessment,
            [control],
            [finding]
        )


@pytest.mark.parametrize(
    'duplicate_type, expected_error',
    [
        ('control', 'Duplicate control identifiers'),
        ('finding', 'Duplicate finding identifiers')
    ]
)
def test_validate_assessment_record_rejects_duplicate_identifiers(
    duplicate_type,
    expected_error
):
    '''
    Verify that the validator rejects duplicate control
    identifiers and duplicate finding identifiers.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create one valid control evaluation.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA coverage requires improvement.'
    )

    # Create one valid finding.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description='MFA is not enforced for all users.',
        likelihood=4,
        impact=5,
        risk_rationale='Unauthorized access could expose sensitive data.',
        recommendation='Enforce MFA for all user accounts.'
    )

    # Start with valid collections.
    controls = [control]
    findings = [finding]

    # Introduce a duplicate identifier in the selected collection.
    # Reusing the same object is sufficient because uniqueness
    # is determined by the identifier, not object identity.
    if duplicate_type == 'control':
        controls.append(control)
    else:
        findings.append(finding)

    # Verify that the appropriate duplicate is rejected.
    with pytest.raises(ValueError, match=expected_error):
        validate_assessment_record(
            assessment,
            controls,
            findings
        )


def test_validate_assessment_record_rejects_unassessed_control():
    '''
    Verify that the validator rejects a finding referencing
    a control that is absent from the assessment.
    '''

    # Create the parent assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Create an evaluated IAM control.
    control = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['EVID-001'],
        observations='MFA is enforced for all users.'
    )

    # Create a finding referencing END-01, which has
    # not been evaluated in this assessment.
    finding = Finding(
        finding_id='FND-001',
        assessment_id='ASM-2026-001',
        control_id='END-01',
        description='Endpoint protection is missing.',
        likelihood=4,
        impact=4,
        risk_rationale='Unprotected devices increase compromise risk.',
        recommendation='Deploy endpoint protection to all devices.'
    )

    # Verify that the invalid control reference is rejected.
    with pytest.raises(ValueError, match='unassessed control'):
        validate_assessment_record(
            assessment,
            [control],
            [finding]
        )


@pytest.mark.parametrize(
    'unsupported_version',
    [
        0,
        2,
        999
    ]
)
def test_deserialize_assessment_record_rejects_unsupported_schema_version(
    unsupported_version,
):
    '''
    Verify that deserialization rejects assessment records
    containing unsupported schema versions.
    '''

    # Create a valid record using the current schema.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    record_data = serialize_assessment_record(
        assessment,
        [],
        []
    )

    # Replace the supported version with an unsupported one.
    record_data['schema_version'] = unsupported_version

    # Verify that deserialization rejects the record.
    with pytest.raises(
        ValueError,
        match='Unsupported assessment record schema version',
    ):
        deserialize_assessment_record(record_data)


@pytest.mark.parametrize(
    'invalid_version',
    [
        '1',
        True,
        False,
        1.0,
        None
    ]
)
def test_deserialize_assessment_record_rejects_invalid_schema_version_type(
    invalid_version,
):
    '''
    Verify that schema versions must be integers and reject
    strings, booleans, floating-point values, and null.
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

    # Generate a valid complete record.
    record_data = serialize_assessment_record(
        assessment,
        [],
        []
    )

    # Replace the valid schema version with an invalid type.
    record_data['schema_version'] = invalid_version

    # Verify that deserialization rejects the invalid type.
    with pytest.raises(
        ValueError,
        match='schema_version must be an integer'
    ):
        deserialize_assessment_record(record_data)


@pytest.mark.parametrize(
    'invalid_structure',
    [
        'missing_schema_version',
        'unexpected_field'
    ]
)
def test_deserialize_assessment_record_rejects_invalid_structure(
    invalid_structure
):
    '''
    Verify that deserialization rejects records with
    missing required sections or unexpected top-level fields.
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

    # Generate a valid complete assessment record.
    record_data = serialize_assessment_record(
        assessment,
        [],
        []
    )

    # Introduce the selected structural defect.
    if invalid_structure == 'missing_schema_version':
        del record_data['schema_version']
    else:
        record_data['unexpected_field'] = 'unexpected value'

    # Verify that the invalid record structure is rejected.
    with pytest.raises(
        ValueError,
        match='missing or unexpected sections'
    ):
        deserialize_assessment_record(record_data)


@pytest.mark.parametrize(
    'field_name, invalid_value, expected_error',
    [
        ('control_assessments', {}, 'Control assessments must be a list'),
        ('control_assessments', 'invalid', 'Control assessments must be a list'),
        ('control_assessments', None, 'Control assessments must be a list'),
        ('findings', {}, 'Findings must be a list'),
        ('findings', 'invalid', 'Findings must be a list'),
        ('findings', None, 'Findings must be a list')
    ]
)
def test_deserialize_assessment_record_rejects_invalid_collection_types(
    field_name,
    invalid_value,
    expected_error,
):
    '''
    Verify that control assessments and findings must
    be represented as lists in stored assessment records.
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

    # Generate a valid versioned assessment record.
    record_data = serialize_assessment_record(
        assessment,
        [],
        []
    )

    # Replace the selected collection with an invalid type.
    record_data[field_name] = invalid_value

    # Verify that deserialization rejects the invalid collection.
    with pytest.raises(ValueError, match=expected_error):
        deserialize_assessment_record(record_data)


@pytest.mark.skipif(
    os.name != 'posix',
    reason='POSIX file permissions are required for this test.',
)
def test_save_assessment_record_uses_restrictive_permissions(tmp_path):
    '''
    Verify that saved assessment records are accessible
    only to their owner on POSIX systems.
    '''

    # Create a valid assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Save the assessment record.
    file_path = tmp_path / 'assessment-record.json'

    save_assessment_record(
        assessment,
        [],
        [],
        file_path
    )

    # Extract the file's POSIX permission bits.
    permissions = file_path.stat().st_mode & 0o777

    # Verify that group and other users have no access.
    assert permissions & 0o077 == 0

    # Verify that the owner can read and write the file.
    assert permissions & 0o600 == 0o600


def test_save_assessment_record_cleans_up_after_publication_failure(
    tmp_path,
):
    '''
    Verify that a failed atomic publication leaves no
    destination file or temporary files behind.
    '''

    # Create a valid assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    file_path = tmp_path / 'assessment-record.json'

    # Simulate a filesystem refusing hard-link creation.
    with patch(
        'src.assessment_storage.os.link',
        side_effect=OSError('Hard links are not supported.')
    ):
        with pytest.raises(
            OSError,
            match='Hard links are not supported'
        ):
            save_assessment_record(
                assessment,
                [],
                [],
                file_path
            )

    # The destination must not have been published.
    assert not file_path.exists()

    # The temporary file must also have been removed.
    assert list(tmp_path.iterdir()) == []


def test_save_assessment_record_preserves_existing_file_on_conflict(
    tmp_path,
):
    '''
    Verify that attempting to save over an existing assessment
    does not modify its original contents.
    '''

    # Create the original assessment.
    original_assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Original Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    file_path = tmp_path / 'assessment-record.json'

    # Save the original assessment.
    save_assessment_record(
        original_assessment,
        [],
        [],
        file_path
    )

    # Capture the exact original file contents.
    original_contents = file_path.read_bytes()

    # Create a different assessment targeting the same file.
    replacement_assessment = Assessment(
        assessment_id='ASM-2026-002',
        organization='Northstar BuildCo',
        assessor='Replacement Assessor',
        assessment_date=date(2026, 11, 2),
        framework='NIST CSF 2.0',
        scope='Third-Party Risk Management'
    )

    # The existing destination must prevent publication.
    with pytest.raises(FileExistsError):
        save_assessment_record(
            replacement_assessment,
            [],
            [],
            file_path
        )

    # Verify that the original bytes remain unchanged.
    assert file_path.read_bytes() == original_contents

    # Verify that the original assessment remains loadable.
    loaded_assessment, controls, findings = load_assessment_record(
        file_path
    )

    assert loaded_assessment == original_assessment
    assert controls == []
    assert findings == []

    # Verify that no temporary files remain.
    assert list(tmp_path.iterdir()) == [file_path]


def test_save_assessment_record_rejects_symlink_destination(
    tmp_path,
):
    '''
    Verify that saving an assessment cannot overwrite
    a file referenced by an existing symbolic link.
    '''

    # Create a file containing information we must preserve.
    protected_file = tmp_path / 'protected.txt'
    protected_file.write_text('Original protected content')

    # Create a symbolic link at the intended assessment path.
    assessment_path = tmp_path / 'ASM-2026-001.json'
    assessment_path.symlink_to(protected_file)

    # Create a valid assessment.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Attempt to save to the existing symbolic link.
    with pytest.raises(FileExistsError):
        save_assessment_record(
            assessment,
            [],
            [],
            assessment_path
        )

    # Verify that the symbolic link remains unchanged.
    assert assessment_path.is_symlink()
    assert assessment_path.resolve() == protected_file.resolve()

    # Verify that the protected file was not modified.
    assert protected_file.read_text() == 'Original protected content'

    # Verify that no temporary files remain.
    assert set(tmp_path.iterdir()) == {
        protected_file,
        assessment_path
    }
