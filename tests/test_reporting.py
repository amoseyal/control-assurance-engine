import pandas as pd

# Import the reporting function that we are about to build.
#
# The function does not exist yet, so this test shoudl initially
# fail during the collection. That is our RED stage of TDD.
from src.reporting import (
    build_control_finding,
    build_findings_dataframe,
    build_executive_summary,
    format_executive_summary,
    build_management_findings,
    format_management_findings,
    generate_management_report,
    export_management_report,
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
        ),

        # OInclude the control's baseline rink ratings.
        likelihood=4,
        impact=4,

        # Provide management-readable context describing the
        # condition identified by the control assessment.
        finding_description=(
            'Three active user accounts were identified without MFA enabled.'
        ),

        # Provide a management action that addresses the
        # condition identified by the control assessment.
        recommendation=(
            'Enable MFA for all active user accounts and verify enrollment.'
        ),
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

    # Verify that the control's risk ratings and calculated
    # risk information are preserved in the finding.
    assert finding['likelihood'] == 4
    assert finding['impact'] == 4
    assert finding['risk_score'] == 16
    assert finding['severity'] == 'HIGH'

    # Verify that the management-readable finding description
    # is preserved in the structured finding.
    assert finding['finding_description'] == (
        'Three active user accounts were identified without MFA enabled.'
    )

    # Verify that the recommended management action is
    # preserved in the structured finding.
    assert finding['recommendation'] == (
        'Enable MFA for all active user accounts and verify enrollment.'
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
        evidence_issues=evidence_issues,

        # Include baseline risk ratings to verify that an
        # unassessed control does not become an active risk finding.
        likelihood=4,
        impact=5
    )

    # A zero assessable population does not provide enough evidence
    # to conclude that the control passed.
    assert finding['result'] == 'NOT ASSESSED'

    # The population and exception metrics should still be accurate.
    assert finding['population_tested'] == 0
    assert finding['exception_count'] == 0
    assert finding['exception_rate'] == 0.0
    
    # A control that could not be assessed shoudl not receive
    # an active finding risk score or severity classification.
    assert finding['risk_score'] is None
    assert finding['severity'] is None



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
        'evidence_issue_count': 1,

        # Include active finding risk information in the
        # structured finding used by the formatter test.
        'likelihood': 4,
        'impact': 4,
        'risk_score': 16,
        'severity': 'HIGH',

        # Include management-readable context appropriate for
        # the END-01 endpoint encryption control.
        'finding_description': (
            'Company-managed endpoints were identified without disk encryption.'
        ),
        'recommendation': (
            'Enable full-disk encryption on all company-managed endpoints.'
        )
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

    # Verify that active finding risk information is included
    # in the homan-readable control finding.
    assert 'Likelihood: 4' in output
    assert 'Impact: 4' in output
    assert 'Risk Score: 16' in output
    assert 'Severity: HIGH' in output

    # Verify that management context is included in the
    # human-readable control finding.
    assert (
        'Finding: Company-managed endpoints were identified without disk encryption.'
        in output
    )

    assert (
        'Recommendation: Enable full-disk encryption on all '
        'company-managed endpoints.'
        in output
    )


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
# CONTROL RESULT AND RISK SEVERITY TESTS
# ============================================================

def test_passing_control_has_no_finding_severity():
    """
    Verify that a passing control does not receive an active
    finding severity even when baseline risk ratings exist.
    """

    # Create an assessable population with no control exceptions.
    assessable_population = pd.DataFrame([
        {'username': 'jcarter'},
        {'username': 'akim'}
    ])

    # No records violate the control requirement.
    exceptions = pd.DataFrame(columns=['username'])

    # No evidence-quality issues prevent assessment.
    evidence_issues = pd.DataFrame(columns=['username'])

    finding = build_control_finding(
        control_id='TEST-01',
        requirement='Test control requirement.',
        assessable_population=assessable_population,
        exceptions=exceptions,
        evidence_issues=evidence_issues,

        # The underlying risk could be significant if
        # this control were to fail.
        likelihood=4,
        impact=4
    )

    # The control itself passed.
    assert finding['result'] == 'PASS'

    # Baseline risk ratings should remain available
    # as contextual information.
    assert finding['likelihood'] == 4
    assert finding['impact'] == 4

    # A passing control should not generate an active
    # risk score or finding severity.
    assert finding['risk_score'] is None
    assert finding['severity'] is None



# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def test_build_executive_summary():
    """
    Test that individual control findings are aggregated into
    executive-level assessment metrics.
    """

    # Create representative control findings with different
    # assessment results, exception counts, and risk severities.
    findings = [
        {
            'control_id': 'IAM-01',
            'result': 'FAIL',
            'exception_count': 3,
            'evidence_issue_count': 2,
            'severity': 'HIGH'
        },
        {
            'control_id': 'END-02',
            'result': 'PASS',
            'exception_count': 0,
            'evidence_issue_count': 0,
            'severity': None
        },
        {
            'control_id': 'TPR-01',
            'result': 'NOT ASSESSED',
            'exception_count': 0,
            'evidence_issue_count': 1,
            'severity': None
        }
    ]

    # Build an executive summary from the individual
    # control assessment results.
    summary = build_executive_summary(findings)

    # Verify the overall control-assessment metrics.
    assert summary['controls_assessed'] == 3
    assert summary['passed'] == 1
    assert summary['failed'] == 1
    assert summary['not_assessed'] == 1

    # Verify aggregated exception and evidence-quality metrics.
    assert summary['total_exceptions'] == 3
    assert summary['evidence_issues'] == 3

    # Verify executive-level severity counts.
    assert summary['high_findings'] == 1
    assert summary['critical_findings'] == 0


def test_format_executive_summary():
    """
    Test that executive-level assessment metrics are converted
    into concise, human-readable management output.
    """

    # Create representative executive-level assessment metrics.
    summary = {
        'controls_assessed': 7,
        'passed': 1,
        'failed': 6,
        'not_assessed': 0,
        'total_exceptions': 9,
        'evidence_issues': 4,
        'high_findings': 6,
        'critical_findings': 0
    }

    # Format the structured metrics as a Markdown table.
    output = format_executive_summary(summary)

    # Verify the table structure.
    assert '| Metric | Result |' in output
    assert '| --- | ---: |' in output

    # Verify the executive metrics are represented correctly.
    assert '| Controls Evaluated | 7 |' in output
    assert '| Passed | 1 |' in output
    assert '| Failed | 6 |' in output
    assert '| Not Assessed | 0 |' in output
    assert '| Total Exceptions | 9 |' in output
    assert '| Evidence Issues | 4 |' in output
    assert '| High Findings | 6 |' in output
    assert '| Critical Findings | 0 |' in output



# ------------------------------------------------------------
# MANAGEMENT FINDINGS
# ------------------------------------------------------------

def test_build_management_findings():
    """
    Test that the management findings summary includes only
    controls with confirmed FAIL results requiring remediation.
    """

    # Create representative findings covering failed, passed,
    # and not-assessed control results.
    findings = [
        {
            'control_id': 'IAM-01',
            'result': 'FAIL',
            'severity': 'HIGH',
            'affected_entities': ['mlopez', 'snguyen']
        },
        {
            'control_id': 'END-02',
            'result': 'PASS',
            'severity': None,
            'affected_entities': []
        },
        {
            'control_id': 'TPR-01',
            'result': 'NOT ASSESSED',
            'severity': None,
            'affected_entities': []
        },
        {
            'control_id': 'TPR-02',
            'result': 'FAIL',
            'severity': 'HIGH',
            'affected_entities': ['VND-002']
        }
    ]

    # Build the management view containing only confirmed
    # control failures that require remediation.
    management_findings = build_management_findings(findings)

    # Verify that only failed controls are included.
    assert len(management_findings) == 2
    assert management_findings[0]['control_id'] == 'IAM-01'
    assert management_findings[1]['control_id'] == 'TPR-02'

    # Verify that PASS and NOT ASSESSED controls are excluded
    # from the remediation-focused management view.
    assert all(
        finding['result'] == 'FAIL'
        for finding in management_findings
    )


def test_format_management_findings():
    """
    Test that failed control findings are converted into a concise,
    actionable management remediation summary.
    """

    # Create representative failed findings containing the
    # information management needs to understand and remediate
    # each confirmed control deficiency.
    management_findings = [
        {
            'control_id': 'IAM-01',
            'severity': 'HIGH',
            'affected_entities': ['mlopez', 'snguyen'],
            'finding_description': (
                'Active user accounts were identified without MFA enabled.'
            ),
            'recommendation': (
                'Enable MFA for all active user accounts and verify enrollment.'
            )
        },
        {
            'control_id': 'TPR-02',
            'severity': 'HIGH',
            'affected_entities': ['VND-002'],
            'finding_description': (
                'Third-party vendors with privileged access were identified '
                'without MFA enabled.'
            ),
            'recommendation': (
                'Require MFA for all third-party vendors with privileged access.'
            )
        }
    ]

    # Format the failed findings into a management-readable
    # remediation summary.
    output = format_management_findings(management_findings)

    # Verify that each failed control and its severity are shown.
    assert '### IAM-01 | HIGH' in output
    assert '### TPR-02 | HIGH' in output

    # Verify that the affected entities are identified.
    assert '**Affected:** mlopez, snguyen' in output
    assert '**Affected:** VND-002' in output

    # Verify that management receives both the finding context
    # and the recommended remediation action.
    assert (
        '**Finding:** Active user accounts were identified without MFA enabled.'
        in output
    )
    assert (
        '**Recommendation:** Enable MFA for all active user accounts '
        'and verify enrollment.'
        in output
    )



# ------------------------------------------------------------
# MANAGEMENT REPORT
# ------------------------------------------------------------

def test_generate_management_report():
    """
    Test that executive metrics and remediation findings are
    assembled into a complete Markdown management report.
    """

    # Create representative executive-level assessment metrics.
    executive_summary = {
        'controls_assessed': 3,
        'passed': 1,
        'failed': 2,
        'not_assessed': 0,
        'total_exceptions': 3,
        'evidence_issues': 1,
        'high_findings': 2,
        'critical_findings': 0
    }

    # Create representative failed controls requiring
    # management remediation.
    management_findings = [
        {
            'control_id': 'IAM-01',
            'severity': 'HIGH',
            'affected_entities': ['mlopez', 'snguyen'],
            'finding_description': (
                'Active user accounts were identified without MFA enabled.'
            ),
            'recommendation': (
                'Enable MFA for all active user accounts and verify enrollment.'
            )
        },
        {
            'control_id': 'TPR-02',
            'severity': 'HIGH',
            'affected_entities': ['VND-002'],
            'finding_description': (
                'Third-party vendors with privileged access were identified '
                'without MFA enabled.'
            ),
            'recommendation': (
                'Require MFA for all third-party vendors with privileged access.'
            )
        }
    ]

    # Generate the Markdown management report.
    report = generate_management_report(
        executive_summary,
        management_findings
    )

    # Verify the report identity and major sections.
    assert '# Northstar BuildCo' in report
    assert '## Cybersecurity Control Assurance Assessment' in report
    assert '## Executive Summary' in report
    assert '## Findings Requiring Remediation' in report

    # Verify that calculated executive metrics are included
    # using the Markdown table format.
    assert '| Controls Evaluated | 3 |' in report
    assert '| Passed | 1 |' in report
    assert '| Failed | 2 |' in report

    # Verify that remediation findings are included.
    assert '### IAM-01 | HIGH' in report
    assert '### TPR-02 | HIGH' in report
    assert (
        '**Recommendation:** Enable MFA for all active user accounts '
        'and verify enrollment.'
        in report
    )


def test_generate_management_report_includes_assessment_context():
    """
    Test that the management report includes basic assessment
    context before presenting assessment results.
    """

    # Create representative executive-level assessment metrics.
    executive_summary = {
        'controls_assessed': 3,
        'passed': 1,
        'failed': 2,
        'not_assessed': 0,
        'total_exceptions': 3,
        'evidence_issues': 1,
        'high_findings': 2,
        'critical_findings': 0
    }

    # No remediation findings are required to test the
    # assessment-context section itself.
    management_findings = []

    # Generate the management report with assessment context.
    report = generate_management_report(
        executive_summary,
        management_findings,
        assessment_date='October 2026',
        assessment_scope=(
            'Identity and Access Management, Endpoint Security, '
            'and Third-Party Risk'
        ),
        framework_alignment='NIST Cybersecurity Framework (CSF) 2.0'
    )

    # Verify that the assessment context is presented near
    # the beginning of the management report.
    assert '**Assessment Date:** October 2026' in report

    assert (
        '**Assessment Scope:** Identity and Access Management, '
        'Endpoint Security, and Third-Party Risk'
        in report
    )

    assert (
        '**Framework Alignment:** '
        'NIST Cybersecurity Framework (CSF) 2.0'
        in report
    )


def test_export_management_report(tmp_path):
    """
    Test that a generated Markdown management report is written
    to the specified output file.
    """

    # Create representative Markdown report content.
    report = (
        '# Northstar BuildCo\n\n'
        '## Cybersecurity Control Assurance Assessment\n\n'
        '## Executive Summary\n\n'
        'Controls Evaluated: 7'
    )

    # Use pytest's temporary directory so the test does not
    # create or modify files in the real project output folder.
    output_file = tmp_path / 'management_report.md'

    # Export the generated management report.
    export_management_report(
        report,
        output_file
    )

    # Verify that the report file was created.
    assert output_file.exists()

    # Verify that the exported file contains exactly the
    # Markdown content supplied to the export function.
    assert output_file.read_text() == report



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