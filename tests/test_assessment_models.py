import pytest

from dataclasses import FrozenInstanceError

from datetime import date, datetime

from src.assessment_models import (
    Assessment,
    ControlAssessment,
    Finding
)


def test_assessment_initialization():
    '''
    Verify that an Assessment instance correctly stores
    the information provided during initialization.
    '''

    # Create a sample cybersecurity assessment engagement.
    assessment = Assessment(
        assessment_id='ASM-2026-001',
        organization='Northstar BuildCo',
        assessor='Test Assessor',
        assessment_date=date(2026, 11, 1),
        framework='NIST CSF 2.0',
        scope='Identity and Access Management'
    )

    # Verify that each field retains its assigned value.
    assert assessment.assessment_id == 'ASM-2026-001'
    assert assessment.organization == 'Northstar BuildCo'
    assert assessment.assessor == 'Test Assessor'
    assert assessment.assessment_date == date(2026, 11, 1)
    assert assessment.framework == 'NIST CSF 2.0'
    assert assessment.scope == 'Identity and Access Management'

@pytest.mark.parametrize(
    'field_name, invalid_value',
    [
        ('assessment_id', ''),
        ('assessment_id', '   '),
        ('organization', '   '),
        ('assessor', None),
        ('framework', 123),
        ('scope', '   ')
    ],
)
def test_assessment_validation(
    field_name,
    invalid_value
    ):
    '''
    Verify that required assessment fields reject
    blank strings and invalid data types.
    '''

    # Start with valid assessment record.
    assessment_data = {
        'assessment_id': 'ASM-2026-001',
        'organization': 'Northstar BuildCo',
        'assessor': 'Test Assessor',
        'assessment_date': date(2026, 11, 1),
        'framework': 'NIST CSF 2.0',
        'scope': 'Identity and Access Management'
    }

    # Replace one valid field with an invalid value for testing.
    assessment_data[field_name] = invalid_value

    # Confirm that validation rejects the invalid record.
    with pytest.raises(ValueError):
        Assessment(**assessment_data)


@pytest.mark.parametrize(
    'invalid_date',
    [
        '2026-11-01',
        None,
        20261101,
    ],
)
def test_assessment_rejects_invalid_dates(
    invalid_date
    ):
    '''
    Verify that assessment_date requires a datetime.date object.
    '''

    with pytest.raises(ValueError):
        Assessment(
            assessment_id='ASM-2026-001',
            organization='Northstart BuildCo',
            assessor='Test Assessor',
            assessment_date=invalid_date,
            framework='NIST CSF 2.0',
            scope='Identity and Access Management'
        )


def test_assessment_rejects_datetime():
    '''
    VErify that assessment_date requires a date-only
    object and rejects datetime timestamps.
    '''

    # Attempt to create an assessment using a datetime
    # object instead of a date-only object.
    with pytest.raises(ValueError, match='assessment_date'):
        Assessment(
            assessment_id='ASM-2026-001',
                        organization='Northstart BuildCo',
                        assessor='Test Assessor',
                        assessment_date=datetime(2026, 11, 1, 14, 30),
                        framework='NIST CSF 2.0',
                        scope='Identity and Access Management'
        )


@pytest.mark.parametrize(
    'field_name, new_value',
    [
        ('assessment_id', 'ASM-2026-002'),
        ('organization', 'Updated Organization'),
        ('assessor', 'Updated Assessor'),
        ('assessment_date', date(2026, 11, 2)),
        ('framework', 'ISO/IEC 27001:2022'),
        ('scope', 'Updated assessment scope'),
    ],
)
def test_assessment_rejects_modifications(
    field_name,
    new_value,
):
    '''
    Verify that a validated Assessment cannot be
    modified after initialization.
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

    # Verify that reassignment of an attribute is rejected.
    with pytest.raises(FrozenInstanceError):
        setattr(assessment, field_name, new_value)

    # Confirm that the original assessment information is preserved.
    assert assessment.assessment_id == 'ASM-2026-001'
    assert assessment.framework == 'NIST CSF 2.0'
    assert assessment.scope == 'Identity and Access Management'


def test_control_assessment_initialization():
    '''
    Verify the a ControlAssessment instance correctly stores
    the information associated with an individual control evaluation.
    '''

    # Create a sample manual assessment of the MFA control.
    control_assessment = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='PARTIALLY_IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=[
            'MFA configuration export',
            'User account review'
        ],
        observations=(
            'Three active user accounts were identified without MFA enabled.'
        ),
    )

    # Verify the assessment and control identifiers.
    assert control_assessment.assessment_id == 'ASM-2026-001'
    assert control_assessment.control_id == 'IAM-01'

    # Verify the assessment method and implementation status.
    assert control_assessment.assessment_method == 'MANUAL'
    assert control_assessment.implementation_status == 'PARTIALLY_IMPLEMENTED'

    # Verify the evidence status.
    assert control_assessment.evidence_status == 'SUFFICIENT'

    # Verify that evidence references are preserved.
    assert control_assessment.evidence_references == (
        'MFA configuration export',
        'User account review'
    )

    # Verify that assessor observations are preserved.
    assert (control_assessment.observations
            == 'Three active user accounts were identified without MFA enabled.'
    )


@pytest.mark.parametrize(
    'invalid_method',
    [
        'UNKNOWN',
        'manual',
        '',
        None,
        123
    ]
)
def test_control_assessment_rejects_invalid_methods(
    invalid_method
    ):
    '''
    Verify that ControlAssessment rejects unsupported
    assessment methods and invalid data types.
    '''

    # Attempt to initialize a control assessment
    # using an invalid assessment method.
    with pytest.raises(ValueError):
        ControlAssessment(
            assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method=invalid_method,
            implementation_status='PARTIALLY_IMPLEMENTED',
            evidence_status='SUFFICIENT',
            evidence_references=[
                'MFA configuration export',
                'User account review'
            ],
            observations=(
                'Three active user accounts were identified without MFA enabled.'
            )
        )


@pytest.mark.parametrize(
    'invalid_status',
    [
        'UNKNOWN',
        'implemented',
        '',
        None,
        123,
        'INSUFFICIENT_EVIDENCE'
    ]
)
def test_control_assessment_rejects_invalid_statuses(
    invalid_status
    ):
    '''
    Verify that ControlAssessment rejects unsupported
    implementation statuses and invalid data types.
    '''

    # Attempt to create control assessment with an
    # unsupported implementation status.
    with pytest.raises(ValueError):
        ControlAssessment(
            assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method='MANUAL',
            implementation_status=invalid_status,
            evidence_status='SUFFICIENT',
            evidence_references=[
                'MFA configuration export',
                'User account review'
            ],
            observations=(
                'Three active user accounts were identified without MFA enabled.'
            )
        )


@pytest.mark.parametrize(
    'field_name, invalid_value',
    [
        ('assessment_id', ''),
        ('assessment_id', '   '),
        ('assessment_id', None),
        ('control_id', ''),
        ('control_id', '   '),
        ('control_id', 123)
    ]
)
def test_control_assessment_rejects_invalid_identifiers(
    field_name,
    invalid_value
    ):
    '''
    Verify that assessment and control identifiers
    must be non-empty strings.
    '''

    # Start with valid control assessment record.
    assessment_data = {
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'assessment_method': 'MANUAL',
        'implementation_status': 'PARTIALLY_IMPLEMENTED',
        'evidence_status': 'SUFFICIENT',
        'evidence_references': [
            'MFA configuration export',

        ],
        'observations': (
                    'Three active user accounts were identified without MFA enabled.'
        )
    }

    # Replace one valid identifier with an invalid value.
    assessment_data[field_name] = invalid_value

    # Verify that the invalid identifier is rejected.
    with pytest.raises(ValueError):
        ControlAssessment(**assessment_data)


@pytest.mark.parametrize(
    'invalid_references',
    [
        None,
        'MFA configuration export',
        123,
        [''],
        ['   '],
        ['MFA configuration export', None],
        ['MFA configuration export', 123]
    ]
)
def test_control_assessment_rejects_invalid_evidence_references(
    invalid_references
    ):
    '''
    Verify that evidence references must be a list
    containing only non-empty strings.
    '''

    # Attempt to initialize a control assessment
    # with invalid evidence references.
    with pytest.raises(ValueError):
        ControlAssessment(
            assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method='MANUAL',
            implementation_status='PARTIALLY_IMPLEMENTED',
            evidence_status='SUFFICIENT',
            evidence_references=invalid_references,
            observations=(
                'Three active user accounts were identified without MFA enabled.'
            )
        )


def test_control_assessment_accepts_empty_evidence_references():
    '''
    Verify that a control assessment can be created
    without evidence references when assessment
    work has not yet been performed.
    '''

    # Create a control assessment that has not yet been evaluated.
    control_assessment = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='NOT_ASSESSED',
        evidence_status='NOT_REVIEWED',
        evidence_references=[],
        observations=''
    )

    # Verify that an empty evidence list is preserved.
    assert control_assessment.evidence_references == ()

    # Verify that the control remains unassessed.
    assert control_assessment.implementation_status == 'NOT_ASSESSED'


@pytest.mark.parametrize(
    'invalid_observations',
    [
        None,
        123,
        ['Three active user accounts were identified without MFA enabled.'],
        {'finding': 'Three active user accounts were identified without MFA enabled.'}
    ],
)
def test_control_assessment_rejects_invalid_observations(
    invalid_observations
    ):
    '''
    Verify that assessor observations must be strings.
    '''

    # Attempt to create a control assessment
    # containing an invalid observations value.
    with pytest.raises(ValueError):
        ControlAssessment(
            assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method='MANUAL',
            implementation_status='PARTIALLY_IMPLEMENTED',
            evidence_status='SUFFICIENT',
            evidence_references=[
                'MFA configuration export',
                'User account review'
            ],
            observations=invalid_observations
        )


@pytest.mark.parametrize(
    'invalid_evidence_status',
    [
        'UNKNOWN',
        'sufficient',
        '',
        None,
        123,
        'MISSING'
    ]
)
def test_control_assessment_rejects_invalid_evidence_statuses(
    invalid_evidence_status
    ):
    '''
    Verify that ControlAssessment rejects unsupported
    evidence statuses and invalid data types.
    '''

    # Create a control assessment using an invalid
    # evidence sufficiency status.
    with pytest.raises(ValueError):
        ControlAssessment(
            assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method='MANUAL',
            implementation_status='NOT_ASSESSED',
            evidence_status=invalid_evidence_status,
            evidence_references=[],
            observations=''
        )


@pytest.mark.parametrize(
    'evidence_status',
    [
        'NOT_REVIEWED',
        'SUFFICIENT',
        'INSUFFICIENT'
    ]
)
def test_control_assessment_accepts_valid_evidence_statuses(
    evidence_status
    ):
    '''
    Verify that all supported evidence sufficiency
    statuses are accepted.
    '''

    # Create a control assessment using a valid status.
    control_assessment = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='NOT_ASSESSED',
        evidence_status=evidence_status,
        evidence_references=[],
        observations=''
    )

    # Verify that the evidence status is preserved.
    assert control_assessment.evidence_status == evidence_status


def test_control_assessment_evidence_references_are_immutable():
    '''
    Verify that evidence references cannot be modified
    after a control assessment is initialized.
    '''

    # Create a valid control assessment.
    control_assessment = ControlAssessment(
         assessment_id='ASM-2026-001',
            control_id='IAM-01',
            assessment_method='MANUAL',
            implementation_status='IMPLEMENTED',
            evidence_status='SUFFICIENT',
            evidence_references=['MFA configuration export'],
            observations='MFA configuration reviewed.'
    )

    # Evidence references should be stored as an immutable tuple.
    assert control_assessment.evidence_references == (
        'MFA configuration export',
    )

    # Tuples do not support appending new references.
    with pytest.raises(AttributeError):
        control_assessment.evidence_references.append('')


@pytest.mark.parametrize(
    'field_name, new_value',
    [
        ('assessment_id', 'ASM-2026-002'),
        ('control_id', 'IAM-02'),
        ('implementation_status', 'NOT_IMPLEMENTED'),
        ('evidence_status', 'INSUFFICIENT'),
        ('evidence_references', ('Invalid replacement',)),
        ('observations', 'Modified observations.'),
    ],
)
def test_control_assessment_rejects_modifications(
    field_name,
    new_value,
):
    '''
    Verify that a validated control assessment
    cannot be modified after initialization.
    '''

    # Create a valid control assessment.
    control_assessment = ControlAssessment(
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        assessment_method='MANUAL',
        implementation_status='IMPLEMENTED',
        evidence_status='SUFFICIENT',
        evidence_references=['MFA configuration export'],
        observations='MFA configuration reviewed.',
    )

    # Verify that reassignment of an attribute is rejected.
    with pytest.raises(FrozenInstanceError):
        setattr(control_assessment, field_name, new_value)

    # Confirm the original values remain unchanged.
    assert control_assessment.implementation_status == 'IMPLEMENTED'
    assert control_assessment.evidence_status == 'SUFFICIENT'
    assert control_assessment.evidence_references == (
        'MFA configuration export',
    )


def test_finding_initialization():
    '''
    Verify that a Finding instance correctly stores
    the details of an identified security issue.
    '''

    # Create a sample security finding related to MFA enforcement.
    finding = Finding(
        finding_id='FND-2026-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description=(
            'Three active user accounts were identified without MFA enabled.'
        ),
        likelihood=4,
        impact=4,
        risk_rationale=(
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        recommendation=(
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    )

    # Verify the finding identifiers and description.
    assert finding.finding_id == 'FND-2026-001'
    assert finding.assessment_id == 'ASM-2026-001'
    assert finding.control_id == 'IAM-01'
    assert finding.description == (
        'Three active user accounts were '
        'identified without MFA enabled.'
    )

    # Verify the likelihood and impact estimations.
    assert finding.likelihood == 4
    assert finding.impact == 4

    # Verify the supporting rationale and recommendation.
    assert finding.risk_rationale == (
        'Accounts without MFA are more susceptible '
        'to unauthorized access following credential compromise.'
    )
    assert finding.recommendation == (
        'Enforce MFA for all active user accounts, '
        'and review approved exceptions.'
    )


@pytest.mark.parametrize(
    'field_name, invalid_value',
    [
        ('finding_id', ''),
        ('finding_id', '   '),
        ('assessment_id', None),
        ('control_id', ''),
        ('description', '   '),
        ('risk_rationale', 123),
        ('recommendation', '')
    ]
)
def test_finding_rejects_invalid_text_fields(
    field_name,
    invalid_value
    ):
    '''
    Verify that Finding rejects blank, missing,
    and incorrectly typed required text fields.
    '''

    # Start with a valid security finding.
    finding_data = {
        'finding_id': 'FND-2026-001',
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'description': 'Three active accounts lack MFA.',
        'likelihood': 4,
        'impact': 4,
        'risk_rationale': (
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        'recommendation': (
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    }

    # Replace one valid field with an invalid value.
    finding_data[field_name] = invalid_value

    # Confirm that the invalid finding is rejected.
    with pytest.raises(ValueError):
        Finding(**finding_data)


@pytest.mark.parametrize(
    'field_name, invalid_value',
    [
        ('likelihood', 0),
        ('likelihood', 6),
        ('likelihood', -1),
        ('likelihood', 3.5),
        ('likelihood', '4'),
        ('likelihood', None),
        ('likelihood', True),
        ('impact', 0),
        ('impact', 6),
        ('impact', 2.5),
        ('impact', '3'),
        ('impact', None),
        ('impact', False)
    ]
)
def test_finding_rejects_invalid_risk_inputs(
    field_name,
    invalid_value
    ):
    '''
    Verify that likelihood and impact must be
    integers between 1 and 5, excluding Booleans.
    '''

    # Start with a valid security finding.
    finding_data = {
        'finding_id': 'FND-2026-001',
        'assessment_id': 'ASM-2026-001',
        'control_id': 'IAM-01',
        'description': 'Three active accounts lack MFA.',
        'likelihood': 4,
        'impact': 4,
        'risk_rationale': (
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        'recommendation': (
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    }

    # Replace one valid risk input with an invalid value.
    finding_data[field_name] = invalid_value

    # Verify that the invalid input is rejected.
    with pytest.raises(ValueError):
        Finding(**finding_data)


@pytest.mark.parametrize(
    'likelihood, impact',
    [
        (1, 1),
        (1, 5),
        (5, 1),
        (5, 5),
        (3, 3)
    ]
)
def test_finding_accepts_valid_risk_boundaries(
    likelihood,
    impact
):
    '''
    Verify that Finding accepts the minimum and
    maximum permitted likelihood and impact values.
    '''

    # Create a finding using valid boundary values.
    finding = Finding(
        finding_id='FND-2026-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description=(
            'Three active user accounts were identified without MFA enabled.'
        ),
        likelihood=likelihood,
        impact=impact,
        risk_rationale=(
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        recommendation=(
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    )

    # Verify that the supplied values are preserved.
    assert finding.likelihood == likelihood
    assert finding.impact == impact


@pytest.mark.parametrize(
    'likelihood, impact, expected_score',
    [
        (1, 1, 1),
        (2, 3, 6),
        (3, 4, 12),
        (4, 4, 16),
        (5, 5, 25)
    ]
)
def test_finding_calculates_risk_score(
    likelihood,
    impact,
    expected_score
):
    '''
    Verify that Finding calculates risk scores
    using likelihood multiplied by impact.
    '''

    # Create a finding with the supplied risk inputs.
    finding = Finding(
        finding_id='FND-2026-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description=(
            'Three active user accounts were identified without MFA enabled.'
        ),
        likelihood=likelihood,
        impact=impact,
        risk_rationale=(
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        recommendation=(
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    )

    # Verify the calculated score matches the expected result.
    assert finding.risk_score == expected_score


@pytest.mark.parametrize(
    'likelihood, impact, expected_severity',
    [
        (1, 4, 'LOW'),          # Upper boundary of LOW
        (1, 5, 'MODERATE'),     # Lower boundary of MODERATE
        (3, 3, 'MODERATE'),     # Upper attainable score in MODERATE
        (2, 5, 'HIGH'),         # Lower boundary of HIGH
        (4, 4, 'HIGH'),         # Upper boundary of HIGH
        (4, 5, 'CRITICAL'),     # CRITICAL classification
        (5, 5, 'CRITICAL')      # Maximum possible risk score
    ]
)
def test_sinfind_classifies_risk_severity(
        likelihood,
        impact,
        expected_severity
):
    '''
    Verify that findings receive the correct severity
    classification based on their calculated risk score.
    '''

    # Create a finding with the supplied risk inputs.
    finding = Finding(
        finding_id='FND-2026-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description=(
            'Three active user accounts were identified without MFA enabled.'
        ),
        likelihood=likelihood,
        impact=impact,
        risk_rationale=(
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        recommendation=(
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    )

    # Verify that the severity matches the expected classification.
    assert finding.risk_severity == expected_severity


@pytest.mark.parametrize(
    'field_name, new_value',
    [
        ('likelihood', 5),
        ('impact', 5),
        ('description', 'Updated finding description')
    ]
)
def test_finding_rejects_modifications(
    field_name,
    new_value
):
    '''
    Verify that a validated Finding cannot be
    modified after initialization.
    '''

    # Create a valid security finding.
    finding = Finding(
        finding_id='FND-2026-001',
        assessment_id='ASM-2026-001',
        control_id='IAM-01',
        description=(
            'Three active user accounts were identified without MFA enabled.'
        ),
        likelihood=2,
        impact=3,
        risk_rationale=(
            'Accounts without MFA are more susceptible '
            'to unauthorized access following credential compromise.'
        ),
        recommendation=(
            'Enforce MFA for all active user accounts, '
            'and review approved exceptions.'
        )
    )

    # Verify that modofications are rejected.
    with pytest.raises(FrozenInstanceError):
        setattr(finding, field_name, new_value)

    # Confirm the original risk calculation is unchanged.
    assert finding.risk_score == 6
    assert finding.risk_severity == 'MODERATE'
