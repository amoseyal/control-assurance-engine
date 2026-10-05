import pandas as pd

# Import the centralized risk-scoring functions so that
# reporting does not ducplicate risk-calculation logic.
from src.risk import calculate_risk_score, classify_risk



# ============================================================
# STRUCTURED CONTROL FINDING BUILDER
# ============================================================

def build_control_finding(
        control_id,
        requirement,
        assessable_population,
        exceptions,
        evidence_issues,
        finding_description=None,
        recommendation=None,
        nist_csf_function = None,
        nist_csf_category = None,
        nist_csf_category_name = None,
        nist_csf_subcategory = None,
        nist_csf_subcategory_outcome = None,
        likelihood = None,
        impact = None,
        identifier_column = 'username'
):
    """
    Build a structured GRC finding from control-assessment results.

    Parameters:
        control_id:
            Unique identifier for the control being assessed.

        requirement:
            Human-readable description of the control requirement.

        assessable_population:
            Records containing enough evidence to evaluate the control.

        exceptions:
            Records confirmed to violate the control requirement.

        evidence_issues:
            Records that could not be fully assessed because required
            evidence was missing or incomplete.

    Returns:
        A dictionary containing the summarized control finding.
    """

    # Count the number of records that could actually be assessed.
    population_tested = len(assessable_population)

    # Count confirmed control exceptions.
    exception_count = len(exceptions)

    # Calculate the percentage of the assessable population that
    # resulted in confirmed control exceptions.
    #
    # We guard against a population of zero so that we do not attempt
    # to divide by zero.
    if population_tested >0:
        exception_rate = round(
            (exception_count / population_tested) * 100,
            1
        )
    else:
        exception_rate = 0.0

    # Determine the overall control-assessment result.
    #
    # If no records were assessable, the available evidence does not
    # support either a PASS or FAIL conclusion.
    #
    # If assessable records exist and at least one confirmed exception
    # is identified, the control fails.
    #
    # Otherwise, the assessed population passed the control test.
    if population_tested == 0:
       result = 'NOT ASSESSED'
    elif exception_count > 0:
       result = 'FAIL'
    else:
        result = 'PASS'

    # Extract the identifiers for entities with confirmed exceptions.
    #
    # The identifier is configurable because different control families
    # operate on different types of evidence. IAM controls use usernames,
    # while endpoint controls use device IDs.
    affected_entities = exceptions[identifier_column].tolist()

    # Calculate an active finding risk only when the control
    # failed and both baseline risk ratings are available.
    #
    # A passing control may still have significant underlaying
    # risk, but it does not represent an active control finding.
    if (
        result == 'FAIL'
        and likelihood is not None
        and impact is not None
    ):
        risk_score = calculate_risk_score(
            likelihood=likelihood,
            impact=impact
        )

        severity = classify_risk(risk_score)

    else:
        risk_score = None
        severity = None

    # Build one structured finding that can later be displayed,
    # exported, or incorporated into a larger assessment report.
    finding = {
        'control_id': control_id,
        'requirement': requirement,

        # Management-readable explanation of the condition
        # identified during control assessment.
        'finding_description': finding_description,

        # Recommended management action for addressing the
        # condition identified by the control assessment.
        'recommendation': recommendation,

        # Preserve the control's NIST CSF 2.0 mapping
        # in the structured finding.
        'nist_csf_function': nist_csf_function,
        'nist_csf_category': nist_csf_category,
        'nist_csf_category_name': nist_csf_category_name,
        'nist_csf_subcategory': nist_csf_subcategory,
        'nist_csf_subcategory_outcome': nist_csf_subcategory_outcome,

        # Store the assessment results.
        'result': result,
        'population_tested': population_tested,
        'exception_count': exception_count,
        'exception_rate': exception_rate,
        'affected_entities': affected_entities,
        'evidence_issue_count': len(evidence_issues),

        # Preserve the control's baseline risk ratings and
        # calculated risk information in the finding.
        'likelihood': likelihood,
        'impact': impact,
        'risk_score': risk_score,
        'severity': severity
    }

    return finding



# ============================================================
# HUMAN-READABLE CONTROL FINDING FORMATTER
# ============================================================

def format_control_finding(finding, entity_label):
    """
    Convert a structured control finding into consistent,
    human-readable report output.

    Args:
        finding:
            Dictionary containing the structured control finding.

        entity_label:
            Human-readable label for the type of affected entity,
            such as 'Accounts' or 'Devices'.

    Returns:
        str:
            Formatted multi-line control finding.
    """

    # Convert the affected-entity list into readable text.
    #
    # Multiple affected entities are separated by commas.
    # If there are no affected entities, display 'None' rather
    # than leaving the report field blank.
    affected_entities = finding['affected_entities']

    if affected_entities:
        affected_text = ', '.join(affected_entities)
    else:
        affected_text = 'None'

    # Build each report field as a separate line.
    #
    # Keeping formatting here rather than in main.py gives every
    # control a consistent presentation format.
    lines = [
        f"Control ID: {finding['control_id']}",
        f"Requirement: {finding['requirement']}",
        f"Result: {finding['result']}",
        f"Population Tested: {finding['population_tested']}",
        f"Exception Count: {finding['exception_count']}",
        f"Exception Rate: {finding['exception_rate']}%",
        f"Affected {entity_label}: {affected_text}",
        f"Evidence Issues: {finding['evidence_issue_count']}",
    ]

    # Include management-readable context when it is available.
    #
    # Using .get() keeps these fields optional so older or simpler
    # findings can still be formatted without raising an error.
    if finding.get('finding_description'):
        lines.append(
            f"Finding: {finding['finding_description']}"
        )

    if finding.get('recommendation'):
        lines.append(
            f"Recommendation: {finding['recommendation']}"
        )

    # Include active finding risk information only when a risk
    # score was calculated.
    #
    # Failed controls can receive an active finding risk score
    # and severity classification. PASS and NOT ASSESSED controls
    # do not represent active risk findings, so their risk fields
    # are intentionally omitted from the human-readable output.
    #
    # Use get() because risk information is optional in a
    # structured finding. Findings without risk data should
    # still be formatted normally.
    if finding.get('risk_score') is not None:
        lines.append(f"Likelihood: {finding['likelihood']}")
        lines.append(f"Impact: {finding['impact']}")
        lines.append(f"Risk Score: {finding['risk_score']}")
        lines.append(f"Severity: {finding['severity']}")

    # Join the individual fields into one multi-line string.
    #
    # The function returns the text rather than printing it
    # directly. This keeps reporting logic reusable for future
    # console output, text files, or other report formats.
    return '\n'.join(lines)



# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def build_executive_summary(findings):
    """
    Aggregate individual control findings into executive-level
    assessment metrics.

    Args:
        findings:
            List of structured control finding dictionaries.

    Returns:
        dict:
            Summary metrics describing control results, exceptions,
            evidence issues, and finding severity.
    """

    # Count the total number of controls included in the assessment.
    controls_assessed = len(findings)

    # Count controls by assessment result.
    passed = sum(
        1 for finding in findings
        if finding['result'] == 'PASS'
    )

    failed = sum(
        1 for finding in findings
        if finding['result'] == 'FAIL'
    )

    not_assessed = sum(
        1 for finding in findings
        if finding['result'] == 'NOT ASSESSED'
    )

    # Aggregate confirmed control exceptions across all findings.
    total_exceptions = sum(
        finding['exception_count']
        for finding in findings
    )

    # Aggregate evidence-quality issues separately from confirmed
    # control exceptions.
    evidence_issues = sum(
        finding['evidence_issue_count']
        for finding in findings
    )

    # Count active findings by executive-level risk severity.
    high_findings = sum(
        1 for finding in findings
        if finding.get('severity') == 'HIGH'
    )

    critical_findings = sum(
        1 for finding in findings
        if finding.get('severity') == 'CRITICAL'
    )

    # Return a structured summary that can later be formatted
    # for management reporting or exported to another format.
    return {
        'controls_assessed': controls_assessed,
        'passed': passed,
        'failed': failed,
        'not_assessed': not_assessed,
        'total_exceptions': total_exceptions,
        'evidence_issues': evidence_issues,
        'high_findings': high_findings,
        'critical_findings': critical_findings
    }


def format_executive_summary(summary):
    """
    Convert structured executive-level assessment metrics into
    a Markdown table for management reporting.

    Args:
        summary:
            Dictionary containing aggregated assessment metrics.

    Returns:
        str:
            Executive summary formatted as a Markdown table.
    """

    # Build a two-column Markdown table so the assessment metrics
    # are easy to scan in management-facing reports.
    lines = [
        '| Metric | Result |',
        '| --- | ---: |',
        f"| Controls Evaluated | {summary['controls_assessed']} |",
        f"| Passed | {summary['passed']} |",
        f"| Failed | {summary['failed']} |",
        f"| Not Assessed | {summary['not_assessed']} |",
        f"| Total Exceptions | {summary['total_exceptions']} |",
        f"| Evidence Issues | {summary['evidence_issues']} |",
        f"| High Findings | {summary['high_findings']} |",
        f"| Critical Findings | {summary['critical_findings']} |"
    ]

    # Join each table row with a newline to produce valid
    # Markdown table syntax.
    return '\n'.join(lines)



# ------------------------------------------------------------
# MANAGEMENT FINDINGS
# ------------------------------------------------------------

def build_management_findings(findings):
    """
    Build a remediation-focused management view containing
    only confirmed control failures.

    Args:
        findings:
            List of structured control finding dictionaries.

    Returns:
        list:
            Structured findings for controls with a FAIL result.
    """

    # Include only confirmed control failures.
    #
    # PASS controls do not require remediation, while
    # NOT ASSESSED controls represent assessment limitations
    # rather than confirmed control deficiencies.
    management_findings = [
        finding
        for finding in findings
        if finding['result'] == 'FAIL'
    ]

    # Preserve each original structured finding so later
    # reporting functions can use its complete metadata.
    return management_findings


def format_management_findings(management_findings):
    """
    Convert failed control findings into a concise,
    management-readable Markdown remediation summary.

    Args:
        management_findings:
            List of structured findings for controls with
            confirmed FAIL results.

    Returns:
        str:
            Failed control findings formatted as Markdown.
    """

    formatted_findings = []

    for finding in management_findings:
        # Convert the affected entity list into readable text.
        # If no affected entities are present, explicitly show
        # that none were identified.
        affected_entities = finding.get('affected_entities', [])

        if affected_entities:
            affected_text = ', '.join(affected_entities)
        else:
            affected_text = 'None'

        # Render each failed control as its own Markdown subsection.
        # Bold labels make the finding, affected population, and
        # remediation recommendation easier for management to scan.
        lines = [
            f"### {finding['control_id']} | {finding['severity']}",
            '',
            f"**Finding:** {finding['finding_description']}",
            '',
            f"**Affected:** {affected_text}",
            '',
            f"**Recommendation:** {finding['recommendation']}"
        ]

        # Store the completed findings block.
        formatted_findings.append('\n'.join(lines))

    # Separate individual control findings with blank lines.
    return '\n\n'.join(formatted_findings)



# ------------------------------------------------------------
# MANAGEMENT REPORT
# ------------------------------------------------------------

def generate_management_report(
    executive_summary,
    management_findings,
    assessment_date=None,
    assessment_scope=None,
    framework_alignment=None
):
    """
    Generate a Markdown management report from executive-level
    assessment metrics and confirmed remediation findings.

    Args:
        executive_summary:
            Dictionary containing aggregated assessment metrics.

        management_findings:
            List of structured findings for controls with
            confirmed FAIL results.

    Returns:
        str:
            Complete management report formatted as Markdown.
    """

    # Reuse the existing formatters so executive metrics and
    # remediation findings remain consistent across console
    # output and the generated management report.
    executive_text = format_executive_summary(
        executive_summary
    )

    management_text = format_management_findings(
        management_findings
    )

    # Build optional assessment context for the management report.
    # Each field is included only when a value is provided so the
    # report generator remains compatible with simpler use cases.
    context_lines = []

    if assessment_date:
        context_lines.append(
            f'**Assessment Date:** {assessment_date}'
        )

    if assessment_scope:
        context_lines.append(
            f'**Assessment Scope:** {assessment_scope}'
        )

    if framework_alignment:
        context_lines.append(
            f'**Framework Alignment:** {framework_alignment}'
        )

    # Separate each context item with a Markdown line break.
    assessment_context = '  \n'.join(context_lines)

    # Assemble the management-facing sections into a single
    # Markdown document.
    report_sections = [
        '# Northstar BuildCo',
        '## Cybersecurity Control Assurance Assessment'
    ]

    # Include assessment context when one or more context
    # fields were supplied.
    if assessment_context:
        report_sections.append(assessment_context)

    report_sections.extend([
        '## Executive Summary',
        executive_text,
        '## Findings Requiring Remediation',
        management_text
    ])

    # Separate report sections with blank lines to produce
    # readable Markdown output.
    return '\n\n'.join(report_sections)


def export_management_report(report, filepath):
    """
    Export a generated Markdown management report to a file.

    Args:
        report:
            String containing the complete Markdown report.

        filepath:
            Path where the management report should be written.

    Returns:
        None
    """

    # Write the generated Markdown report to the specified
    # output file using UTF-8 encoding.
    filepath.write_text(
        report,
        encoding='utf-8'
    )



# ============================================================
# FINDINGS DATAFRAME BUILDER
# ============================================================

def build_findings_dataframe(findings):
    """
    Convert a collection of structured control findings into
    a pandas DataFrame for reporting and export.

    Args:
        findings:
            List of dictionaries containing structured
            control-assessment findings.

    Returns:
        pd.DataFrame:
            Tabular representation of the control findings.
    """

    # Convert each structured finding dictionary into a row
    # in a pandas DataFrame.
    findings_dataframe = pd.DataFrame(findings)

    # Convert each structured finding dictionary into a row
    # in a pandas DataFrame.
    findings_dataframe = pd.DataFrame(findings)

    # Convert affected-entity lists into clean, report-ready text.
    #
    # Multiple entities are separated by commas, while an empty
    # list becomes an empty string. This prevents Python list
    # notation such as "['user1', 'user2']" from appearing in
    # exported reports.
    findings_dataframe['affected_entities'] = (
        findings_dataframe['affected_entities'].apply(
            lambda entities: ', '.join(entities)
        )
    )


    return findings_dataframe



# ============================================================
# FINDINGS CSV EXPORTER
# ============================================================

def export_findings_csv(findings_dataframe, output_file):
    """
    Export a findings DataFrame to a CSV file.

    Args:
        findings_dataframe:
            DataFrame containing structured control findings.

        output_file:
            Path where the CSV file should be written.
    """

    # Export the findings without the pandas DataFrame index.
    #
    # The index is an internal pandas row identifier and is not
    # part of the control-assessment data, so it should not appear
    # as an extra column in the exported CSV file.
    findings_dataframe.to_csv(
        output_file,
        index=False
    )