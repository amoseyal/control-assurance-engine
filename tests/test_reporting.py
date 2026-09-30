import pandas as pd

# Import the reporting function that we are about to build.
#
# The function does not exist yet, so this test shoudl initially
# fail during the collection. That is our RED stage of TDD.
from src.reporting import (
    build_control_finding,
    build_findings_dataframe,
    export_findings_csv,
    format_control_finding
)



# ============================================================
# STRUCTURED CONTROL FINDING TESTS
# ============================================================

def test_build_iam_01_finding():
    """
    Test that IAM-01 assessment results are converted into
    a structured GRC finding with the correct metrics.
    """

    # Create the assessable population for IAM-01.
    #
    # these six accounts are active and contain sufficient evidence
    # for us to determine whther the control is operating as required.
    assessable_users = pd.DataFrame([
        {'username': 'jcarter'},
        {'username': 'mlopez'},
        {'username': 'akim'},
        {'username': 'dthomas'},
        {'username': 'snguyen'},
        {'username': 'kpatel'}
    ])

    # Create the confirmed control exceptions.
    #
    # These are active accounts that do not have MFA enabled.
    exceptions = pd.DataFrame([
        {'username': 'mlopez'},
        {'username': 'snguyen'}
    ])

    # Create the evidence-wuality issues separately.
    #
    # tgreen cannot be included in the asessable population because
    # the account's enabled status is unknown.
    evidence_issues = pd.DataFrame([
        {'username': 'tgreen'}
    ])

    # Build the structured IAM-01 finding.
    finding = build_control_finding(
        control_id = 'IAM-01',
        requirement = 'All active user accounts must have MFA enabled.',
        assessable_population = assessable_users,
        exceptions = exceptions,
        evidence_issues = evidence_issues,

        # Include the control's NIST CSF 2.0 mapping in the finding.
        nist_csf_function='Protect',
        nist_csf_category='PR.AA',
        nist_csf_subcategory='PR.AA-03',

        # Include the human-readable NIST CSF 2.0 metadata
        # along with the framework codes.
        nist_csf_category_name=(
            'Identity Management, Authentication, and Access Control'
        ),
        nist_csf_subcategory_outcome=(
            'Users, services, and hardware are authenticated'
        )
    )

    # Verify the identity and requirement of the control being reported.
    assert finding['control_id'] == 'IAM-01'
    assert finding['requirement'] == (
        'All active user accounts must have MFA enabled.'
    )

    # Six active accounts contain sufficient evidence to be asessed.
    assert finding['population_tested'] == 6

    # Two of those six accounts failed the control.
    assert finding['exception_count'] == 2

    # 2 exceptions / 6 assessable account = 33.3%
    assert finding['exception_rate'] == 33.3

    # Because at least one confirmed exception exists,
    # the overall control result should be FAIL.
    assert finding['result'] == 'FAIL'

    # The finding should preserve the identities of the accounts
    # responsible for the confirmed control exception.
    assert finding['affected_entities'] == ['mlopez', 'snguyen']
    
    # Evidence-quality problems should also be quantified separately.
    assert finding['evidence_issue_count'] == 1

    # Verify that the NIST CSF mapping is preserved
    # in the structured control finding.
    assert finding['nist_csf_function'] == 'Protect'
    assert finding['nist_csf_category'] == 'PR.AA'
    assert finding['nist_csf_subcategory'] == 'PR.AA-03'

    # Verify that the human-readable NIST CSF metadata
    # is preserved in the structured finding.
    assert finding['nist_csf_category_name'] == (
        'Identity Management, Authentication, and Access Control'
    )

    assert finding['nist_csf_subcategory_outcome'] == (
        'Users, services, and hardware are authenticated'
    )


def test_build_end_01_finding():
    """
    Test that a structured END-01 finding can use device IDs
    rather than usernames as the affected entity identifier.
    """

    # Create a controlled assessable population of six
    # company-managed endpoints.
    assessable_population = pd.DataFrame([
        {'device_id': 'DEV-001'},
        {'device_id': 'DEV-002'},
        {'device_id': 'DEV-003'},
        {'device_id': 'DEV-004'},
        {'device_id': 'DEV-005'},
        {'device_id': 'DEV-006'}
    ])

    # Two of the six assessable endpoints violate END-01.
    exceptions = pd.DataFrame([
        {'device_id': 'DEV-002'},
        {'device_id': 'DEV-005'}
    ])

    # One additional managed endpoint has insufficient evidence
    # and therefore is not part of the assessable population.
    evidence_issues = pd.DataFrame([
        {'device_id': 'DEV-007'}
    ])

    # Build the finding using device_id as the identifier
    # for affected entities.
    finding = build_control_finding(
        control_id='END-01',
        requirement='Company-managed endpoints must use disk encryption.',
        assessable_population=assessable_population,
        exceptions=exceptions,
        evidence_issues=evidence_issues,
        identifier_column='device_id'
    )

    # Verify the calculated control metrics.
    assert finding['population_tested'] == 6
    assert finding['exception_count'] == 2
    assert finding['exception_rate'] == 33.3
    assert finding['result'] == 'FAIL'

    # The reporting layer should return a neutral affected-entities
    # field that works for users, devices, and future evidence types.
    assert finding['affected_entities'] == [
        'DEV-002',
        'DEV-005'
    ]

    # DEV-007 is tracked separately as an evidence-quality issue.
    assert finding['evidence_issue_count'] == 1


def test_build_control_finding_returns_not_assessed_for_zero_population():
    """
    Verify that a control with no assessable population is reported
    as NOT ASSESSED rather than incorrectly reported as PASS.
    """
    assessable_population = pd.DataFrame()
    exceptions = pd.DataFrame(columns=['username'])
    evidence_issues = pd.DataFrame(columns=['username'])

    # Build a finding when no records were available for assessment.
    finding = build_control_finding(
        control_id='TEST-01',
        requirement='Test control requirement.',
        assessable_population=assessable_population,
        exceptions=exceptions,
        evidence_issues=evidence_issues
    )

    # A zero assessable population does not provide enough evidence
    # to conclude that the control passed.
    assert finding['result'] == 'NOT ASSESSED'

    # The population and exception metrics should still be accurate.
    assert finding['population_tested'] == 0
    assert finding['exception_count'] == 0
    assert finding['exception_rate'] == 0.0



# ============================================================
# HUMAN-READABLE CONTROL FINDING FORMATTER TESTS
# ============================================================

def test_format_control_finding():
    """
    Test that a structured control finding is converted into
    consistent, human-readable report output.
    """

    # Create a representative endpoint control finding.
    finding = {
        'control_id': 'END-01',
        'requirement': (
            'Company-managed endpoints must use disk encryption.'
        ),
        'result': 'FAIL',
        'population_tested': 6,
        'exception_count': 2,
        'exception_rate': 33.3,
        'affected_entities': ['DEV-002', 'DEV-005'],
        'evidence_issue_count': 1
    }

    # Format the structured finding for human-readable output.
    output = format_control_finding(
        finding,
        entity_label='Devices'
    )

    # Verify that the important finding information appears
    # in the formatted output.
    assert 'Control ID: END-01' in output
    assert (
        'Requirement: Company-managed endpoints must use '
        'disk encryption.'
    ) in output
    assert 'Result: FAIL' in output
    assert 'Population Tested: 6' in output
    assert 'Exception Count: 2' in output
    assert 'Exception Rate: 33.3%' in output
    assert 'Affected Devices: DEV-002, DEV-005' in output
    assert 'Evidence Issues: 1' in output


def test_format_control_finding_with_no_affected_entities():
    """
    Test that a control finding displays 'None' when there
    are no affected entities.
    """

    # Create a passing control finding with no exceptions
    # and therefore no affected devices.
    finding = {
        'control_id': 'END-02',
        'requirement': (
            'Company-managed endpoints must have endpoint '
            'protection enabled.'
        ),
        'result': 'PASS',
        'population_tested': 7,
        'exception_count': 0,
        'exception_rate': 0.0,
        'affected_entities': [],
        'evidence_issue_count': 0
    }

    # Format the finding using the device entity label.
    output = format_control_finding(
        finding,
        entity_label='Devices'
    )

    # A control with no affected entities should explicitly
    # display 'None' rather than leaving the field blank.
    assert 'Affected Devices: None' in output

    # Confirm that the PASS result is also preserved.
    assert 'Result: PASS' in output



# ------------------------------------------------------------------
# TEST CONTROL FINDING FORMATTER
# ------------------------------------------------------------------

def test_build_findings_dataframe():
    """
    Verify that multiple structured control findings can be
    combined into a DataFrame for reporting and export.
    """
    findings = [
        {
            'control_id': 'IAM-01',
            'requirement': 'All active user accounts must have MFA enabled.',
            'result': 'FAIL',
            'population_tested': 8,
            'exception_count': 3,
            'exception_rate': 37.5,
            'affected_entities': ['mlopez', 'jparis', 'snguyen'],
            'evidence_issue_count': 2
        },
        {
            'control_id': 'END-02',
            'requirement': (
                'Company-managed endpoints must have '
                'endpoint protection enabled.'
            ),
            'result': 'PASS',
            'population_tested': 7,
            'exception_count': 0,
            'exception_rate': 0.0,
            'affected_entities': [],
            'evidence_issue_count': 0
        }
    ]

    # Convert the structured findings into a tabular DataFrame
    # that can later be exported to a CSV file.
    findings_dataframe = build_findings_dataframe(findings)

    # Both control findings should be represented as rows.
    assert len(findings_dataframe) == 2

    # Control identifiers should remain in their original order.
    assert findings_dataframe['control_id'].tolist() == [
        'IAM-01',
        'END-02'
    ]

    # Important assessment results and metrics should be
    # preserved in the tabular representation.
    assert findings_dataframe['result'].tolist() == [
        'FAIL',
        'PASS'
    ]

    assert findings_dataframe['exception_count'].tolist() == [
        3,
        0
    ]

    # Affected entities should be converted from Python lists
    # into clean, report-ready text.
    assert findings_dataframe['affected_entities'].tolist() == [
        'mlopez, jparis, snguyen',
        ''
    ]



# ============================================================
# FINDINGS CSV EXPORT TESTS
# ============================================================

def test_export_findings_csv(tmp_path):
    """
    Verify that a findings DataFrame can be exported to a CSV file.
    """
    findings_dataframe = pd.DataFrame([
        {
            'control_id': 'IAM-01',
            'result': 'FAIL',
            'population_tested': 8,
            'exception_count': 3,
            'exception_rate': 37.5,
            'evidence_issue_count': 2
        },
        {
            'control_id': 'END-02',
            'result': 'PASS',
            'population_tested': 7,
            'exception_count': 0,
            'exception_rate': 0.0,
            'evidence_issue_count': 0
        }
    ])

    # Create a temporary output path supplied by pytest.
    #
    # Using tmp_path prevents the test from creating or overwriting
    # files in the project's real output directory.
    output_file = tmp_path / 'control_findings.csv'

    # Export the findings DataFrame to the temporary CSV file.
    export_findings_csv(
        findings_dataframe,
        output_file
    )

    # Verify that the export actually created the file.
    assert output_file.exists()

    # Load the exported CSV back into pandas so that we can
    # verify the data survived the export process correctly.
    exported_findings = pd.read_csv(output_file)

    assert len(exported_findings) == 2

    assert exported_findings['control_id'].tolist() == [
        'IAM-01',
        'END-02'
    ]

    assert exported_findings['result'].tolist() == [
        'FAIL',
        'PASS'
    ]