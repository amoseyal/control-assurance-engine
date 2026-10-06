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


def format_executive_assessment(summary):
    """
    Convert executive-level assessment metrics into a concise
    narrative interpretation for management.

    Args:
        summary:
            Dictionary containing aggregated assessment metrics.

    Returns:
        str:
            Executive-level narrative assessment of the results.
    """

    # Convert the small numeric values used in the assessment
    # into words for more natural management-facing prose.
    number_words = {
        0: 'zero',
        1: 'one',
        2: 'two',
        3: 'three',
        4: 'four',
        5: 'five',
        6: 'six',
        7: 'seven',
        8: 'eight',
        9: 'nine',
        10: 'ten'
    }

    controls_assessed = summary['controls_assessed']
    failed = summary['failed']
    high_findings = summary['high_findings']
    critical_findings = summary['critical_findings']

    # Use words when the value is available in the small
    # management-reporting range; otherwise fall back to the
    # numeric value.
    controls_text = number_words.get(
        controls_assessed,
        str(controls_assessed)
    )

    failed_text = number_words.get(
        failed,
        str(failed)
    )

    high_text = number_words.get(
        high_findings,
        str(high_findings)
    )

    # Capitalize the first number because it begins the
    # executive assessment statement.
    failed_text = failed_text.capitalize()

    assessment_parts = [
        (
            f'{failed_text} of {controls_text} controls evaluated '
            'resulted in confirmed exceptions requiring remediation.'
        )
    ]

    # Describe critical-severity results without implying that
    # the absence of Critical findings means the assessment is
    # free of significant risk.
    if critical_findings == 0:
        assessment_parts.append(
            'No critical-severity findings were identified.'
        )
    else:
        critical_text = number_words.get(
            critical_findings,
            str(critical_findings)
        )

        assessment_parts.append(
            f'{critical_text.capitalize()} findings were rated Critical.'
        )

    # Summarize High findings separately because they remain
    # significant even when no Critical findings are present.
    if high_findings > 0:
        assessment_parts.append(
            f'{high_text.capitalize()} findings were rated High '
            'based on the defined Northstar BuildCo risk criteria.'
        )

    return ' '.join(assessment_parts)


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

    # Convert the executive metrics into a concise narrative
    # interpretation for management.
    executive_assessment = format_executive_assessment(
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
        executive_assessment,
        '## Findings Requiring Remediation',
        management_text
    ])

    # Separate report sections with blank lines to produce
    # readable Markdown output.
    return '\n\n'.join(report_sections)


def export_management_report(report, filepath):
    """
    Export a generated management report to a file.

    The report may be formatted as Markdown, HTML, or another
    text-based reporting format.

    Trailing whitespace is removed from each line while preserving
    whether the original report ends with a newline.
    """
    cleaned_report = '\n'.join(
        line.rstrip()
        for line in report.splitlines()
    )

    # Preserve the original report's final-newline behavior rather
    # than adding a newline that was not present in the source.
    if report.endswith('\n'):
        cleaned_report += '\n'

    filepath.write_text(
        cleaned_report,
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



# ============================================================
# HTML MANAGEMENT REPORT GENERATOR
# ============================================================

def format_html_control_results(findings):
    """
    Format all control-assessment findings as HTML result cards.

    Unlike the management findings section, this function includes
    every assessed control regardless of whether the result is PASS,
    FAIL, or NOT ASSESSED.

    Args:
        findings:
            List of structured control finding dictionaries.

    Returns:
        str:
            HTML containing one result card for each control.
    """

    control_cards = []

    for finding in findings:
        # Risk information is only active for failed controls.
        # PASS and NOT ASSESSED findings may therefore have no
        # severity or risk score.
        severity = finding.get('severity') or 'N/A'
        risk_score = finding.get('risk_score')

        # Convert assessment values into CSS-safe class names.
        # These classes affect presentation only; they do not
        # change the underlying control result or risk severity.
        result_class = finding['result'].lower().replace(' ', '-')

        severity_value = finding.get('severity')
        if severity_value is None:
            severity_class = 'none'
        else:
            severity_class = severity_value.lower()

        if risk_score is None:
            risk_score_text = 'N/A'
        else:
            risk_score_text = str(risk_score)

        # Build one HTML card using values already calculated by
        # the control-assessment and risk-evaluation layers.
        card = f"""
            <article class="control-card control-{result_class}">
                <div class="control-card-header">
                    <h3>{finding['control_id']}</h3>

                    <div class="control-status">
                        <span class="result-badge result-{result_class}">
                            {finding['result']}
                        </span>

                        <span class="severity-badge severity-{severity_class}">
                            {severity}
                        </span>
                    </div>
                </div>

                <p class="control-requirement">
                    {finding['requirement']}
                </p>

                <dl class="control-metrics">
                    <div>
                        <dt>NIST CSF</dt>
                        <dd>{finding['nist_csf_subcategory']}</dd>
                    </div>

                    <div>
                        <dt>Population Tested</dt>
                        <dd>{finding['population_tested']}</dd>
                    </div>

                    <div>
                        <dt>Exceptions</dt>
                        <dd>{finding['exception_count']}</dd>
                    </div>

                    <div>
                        <dt>Exception Rate</dt>
                        <dd>{finding['exception_rate']}%</dd>
                    </div>

                    <div>
                        <dt>Evidence Issues</dt>
                        <dd>{finding['evidence_issue_count']}</dd>
                    </div>

                    <div>
                        <dt>Risk Score</dt>
                        <dd>{risk_score_text}</dd>
                    </div>
                </dl>
            </article>
        """

        control_cards.append(card)

    # Combine all control cards into one HTML block.
    return '\n'.join(control_cards)


def format_html_management_findings(management_findings):
    """
    Format remediation-focused management findings as HTML.

    This function presents only findings that require management
    action. It does not perform control assessment, risk scoring,
    or remediation prioritization.

    Args:
        management_findings:
            List of remediation-focused finding dictionaries produced
            by build_management_findings().

    Returns:
        String containing HTML for the management findings.
    """
    finding_cards = []

    for finding in management_findings:
        # Present affected entities as a readable comma-separated list.
        affected_entities = ', '.join(finding['affected_entities'])

        card = f"""
            <article class="finding-card">
                <div class="finding-card-header">
                    <h3>{finding['control_id']}</h3>

                    <span class="severity-badge severity-{finding['severity'].lower()}">
                        {finding['severity']}
                    </span>
                </div>

                <div class="finding-content">
                    <div class="finding-detail">
                        <h4>Finding</h4>
                        <p>{finding['finding_description']}</p>
                    </div>

                    <div class="finding-detail">
                        <h4>Affected</h4>
                        <p>{affected_entities}</p>
                    </div>

                    <div class="finding-detail">
                        <h4>Recommendation</h4>
                        <p>{finding['recommendation']}</p>
                    </div>
                </div>
            </article>
        """

        finding_cards.append(card)

    return '\n'.join(finding_cards)


def format_html_control_outcomes(summary):
    """
    Format control-outcome metrics as an HTML visual.

    The function consumes the existing executive-summary metrics
    rather than recalculating assessment results from findings.

    Args:
        summary:
            Executive-summary dictionary produced by
            build_executive_summary().

    Returns:
        String containing HTML for the control-outcomes visual.
    """
    controls_evaluated = summary['controls_assessed']

    # Avoid division by zero when a report contains no controls.
    if controls_evaluated == 0:
        passed_percent = 0
        failed_percent = 0
        not_assessed_percent = 0
    else:
        passed_percent = (
            summary['passed'] / controls_evaluated * 100
        )
        failed_percent = (
            summary['failed'] / controls_evaluated * 100
        )
        not_assessed_percent = (
            summary['not_assessed'] / controls_evaluated * 100
        )

    return f"""
        <div class="visual-card">
            <div class="visual-header">
                <h3>Control Outcomes</h3>
                <p>Distribution of evaluated control results.</p>
            </div>

            <div class="outcome-bar">
                <div
                    class="outcome-segment outcome-pass"
                    style="width: {passed_percent:.1f}%"
                ></div>

                <div
                    class="outcome-segment outcome-fail"
                    style="width: {failed_percent:.1f}%"
                ></div>

                <div
                    class="outcome-segment outcome-not-assessed"
                    style="width: {not_assessed_percent:.1f}%"
                ></div>
            </div>

            <div class="outcome-legend">
                <div>
                    <span class="legend-marker legend-pass"></span>
                    <span>Passed</span>
                    <strong>{summary['passed']}</strong>
                </div>

                <div>
                    <span class="legend-marker legend-fail"></span>
                    <span>Failed</span>
                    <strong>{summary['failed']}</strong>
                </div>

                <div>
                    <span
                        class="legend-marker legend-not-assessed"
                    ></span>
                    <span>Not Assessed</span>
                    <strong>{summary['not_assessed']}</strong>
                </div>
            </div>
        </div>
    """


def format_html_finding_severity(summary):
    """
    Format active finding severity metrics as an HTML visual.

    Severity applies only to failed controls with active risk.
    PASS and NOT ASSESSED controls are therefore excluded from
    the severity distribution.

    The function consumes the existing executive-summary metrics
    rather than recalculating risk or severity.

    Args:
        summary:
            Executive-summary dictionary produced by
            build_executive_summary().

    Returns:
        String containing HTML for the finding-severity visual.
    """
    high_findings = summary['high_findings']
    critical_findings = summary['critical_findings']

    # The severity population includes only findings that currently
    # have an active High or Critical severity classification.
    severity_findings = high_findings + critical_findings

    # Avoid division by zero when no active severity findings exist.
    if severity_findings == 0:
        high_percent = 0
        critical_percent = 0
    else:
        high_percent = (
            high_findings / severity_findings * 100
        )
        critical_percent = (
            critical_findings / severity_findings * 100
        )

    return f"""
        <div class="visual-card">
            <div class="visual-header">
                <h3>Finding Severity</h3>
                <p>
                    Severity distribution for findings with
                    active risk.
                </p>
            </div>

            <div class="severity-bar">
                <div
                    class="severity-segment severity-bar-high"
                    style="width: {high_percent:.1f}%"
                ></div>

                <div
                    class="severity-segment severity-bar-critical"
                    style="width: {critical_percent:.1f}%"
                ></div>
            </div>

            <div class="severity-legend">
                <div>
                    <span class="legend-marker legend-high"></span>
                    <span>High</span>
                    <strong>{high_findings}</strong>
                </div>

                <div>
                    <span class="legend-marker legend-critical"></span>
                    <span>Critical</span>
                    <strong>{critical_findings}</strong>
                </div>
            </div>
        </div>
    """


def format_html_evidence_comparison(findings):
    """
    Format control exceptions and evidence issues as an HTML visual.

    The comparison preserves the distinction between confirmed
    control exceptions and evidence-quality issues. It consumes
    existing assessment results and does not recalculate control
    outcomes or risk.

    Args:
        findings:
            List of structured control-assessment findings.

    Returns:
        String containing HTML for the evidence comparison visual.
    """
    comparison_rows = []

    # Determine the largest count so all bars can be scaled against
    # the same reference point while preserving the actual values.
    max_count = max(
        (
            max(
                finding['exception_count'],
                finding['evidence_issue_count']
            )
            for finding in findings
        ),
        default=0
    )

    for finding in findings:
        exception_count = finding['exception_count']
        evidence_issue_count = finding['evidence_issue_count']

        # Convert counts into relative bar widths for presentation.
        # The displayed numbers remain the authoritative values.
        if max_count == 0:
            exception_percent = 0
            evidence_percent = 0
        else:
            exception_percent = (
                exception_count / max_count * 100
            )
            evidence_percent = (
                evidence_issue_count / max_count * 100
            )

        row = f"""
            <div class="comparison-row">
                <div class="comparison-control">
                    {finding['control_id']}
                </div>

                <div class="comparison-measure">
                    <span class="comparison-label">Exceptions</span>
                    <div class="comparison-track">
                        <div
                            class="comparison-bar comparison-exception"
                            style="width: {exception_percent:.1f}%"
                        ></div>
                    </div>
                    <strong>{exception_count}</strong>
                </div>

                <div class="comparison-measure">
                    <span class="comparison-label">Evidence Issues</span>
                    <div class="comparison-track">
                        <div
                            class="comparison-bar comparison-evidence"
                            style="width: {evidence_percent:.1f}%"
                        ></div>
                    </div>
                    <strong>{evidence_issue_count}</strong>
                </div>
            </div>
        """

        comparison_rows.append(row)

    return f"""
        <div class="visual-card visual-card-wide">
            <div class="visual-header">
                <h3>Exceptions vs. Evidence Issues by Control</h3>
                <p>
                    Confirmed control exceptions are shown separately
                    from evidence-quality issues.
                </p>
            </div>

            <div class="comparison-chart">
                {''.join(comparison_rows)}
            </div>
        </div>
    """


def format_html_report(
        findings,
        assessment_date=None,
        assessment_scope=None,
        framework_alignment=None):
    """
    Format control-assurance findings as an HTML management report.

    This function is responsible only for presentation. It does not
    recalculate control results, exception rates, risk scores, or severity.
    Those values come from the completed assessment findings and the
    existing executive-summary aggregation logic.

    Args:
        findings:
            List of structured control finding dictionaries.

    Returns:
        str:
            A complete HTML document representing the management report.
    """

    # Reuse the existing executive-summary logic so the HTML and
    # Markdown reports are based on the same assessment metrics.
    summary = build_executive_summary(findings)

    # Reuse the existing remediation-focused finding logic so the
    # HTML and Markdown reports identify the same management actions.
    management_findings = build_management_findings(findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Control Assurance Engine | Management Report</title>
    <style>
        /* ---------- Base Report Styling ---------- */

        /*
        Apply predictable sizing so padding and borders are included
        within each element's declared dimensions.
        */
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: #f3f5f7;
            color: #24303d;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Arial,
                sans-serif;
            line-height: 1.5;
        }}

        /*
        Main report container. The white document surface separates
        the management report from the browser background.
        */
        main {{
            width: min(1180px, calc(100% - 48px));
            margin: 40px auto;
            background: #ffffff;
            border: 1px solid #dfe4e8;
            border-radius: 10px;
            padding: 48px;
            box-shadow: 0 8px 24px rgba(20, 34, 48, 0.08);
        }}

        /* ---------- Report Header ---------- */

        header {{
            padding-bottom: 28px;
            margin-bottom: 36px;
            border-bottom: 3px solid #17324d;
        }}

        header h1 {{
            margin: 0;
            color: #17324d;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        header h2 {{
            margin: 8px 0 0;
            color: #65717d;
            font-size: 18px;
            font-weight: 500;
        }}

        /* ---------- Assessment Context ---------- */

        /*
        Assessment metadata establishes when the review was performed,
        what was in scope, and which framework informed the assessment.
        */
        .assessment-context {{
            display: grid;
            grid-template-columns: 1fr 2fr 1.5fr;
            gap: 18px;
            margin-top: 24px;
            padding-top: 20px;
            border-top: 1px solid #dfe4e8;
        }}

        .assessment-context > div {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .assessment-context span {{
            color: #71808d;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.4px;
            text-transform: uppercase;
        }}

        .assessment-context strong {{
            color: #364553;
            font-size: 13px;
            font-weight: 600;
            line-height: 1.5;
        }}

        /* ---------- Report Sections ---------- */

        section {{
            margin-top: 40px;
        }}

        section > h2 {{
            margin: 0 0 20px;
            color: #17324d;
            font-size: 22px;
            font-weight: 650;
        }}

        /* ---------- Executive Summary Metrics ---------- */

        /*
        Display the eight executive metrics as two rows of four
        cards on standard desktop displays.
        */
        .metrics {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }}

        .metric {{
            min-height: 110px;
            padding: 20px;
            background: #f8fafb;
            border: 1px solid #dfe4e8;
            border-radius: 8px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}

        .metric-value {{
            display: block;
            margin-bottom: 6px;
            color: #17324d;
            font-size: 30px;
            font-weight: 700;
            line-height: 1;
        }}

        .metric-label {{
            display: block;
            color: #65717d;
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 0.3px;
            text-transform: uppercase;
        }}

        /* ---------- Semantic Metric States ---------- */

        /*
        Successful control outcomes use restrained green to make
        favorable assessment results immediately recognizable.
        */
        .metric-passed {{
            border-left: 4px solid #2f7d5a;
            background: #f3faf6;
        }}

        .metric-passed .metric-value {{
            color: #2f7d5a;
        }}

        /*
        Confirmed control failures use red. This styling represents
        the control result and is separate from risk severity.
        */
        .metric-failed {{
            border-left: 4px solid #b54747;
            background: #fdf6f6;
        }}

        .metric-failed .metric-value {{
            color: #a33f3f;
        }}

        /*
        Evidence-quality issues use amber because deficient evidence
        is not equivalent to a confirmed control failure.
        */
        .metric-evidence {{
            border-left: 4px solid #c58a2b;
            background: #fdf9f1;
        }}

        .metric-evidence .metric-value {{
            color: #9a681e;
        }}

        /*
        Exception volume receives visual emphasis without assigning
        risk severity to the aggregate exception count.
        */
        .metric-exceptions {{
            border-left: 4px solid #657b8f;
        }}

        /*
        High-severity findings receive stronger management emphasis
        while remaining visually distinct from the FAIL result.
        */
        .metric-high {{
            border-left: 4px solid #b85c38;
            background: #fdf7f3;
        }}

        .metric-high .metric-value {{
            color: #a34d2f;
        }}

        /*
        Critical severity is reserved for the strongest risk signal.
        The styling remains available even when the current count is 0.
        */
        .metric-critical {{
            border-left: 4px solid #8f2d2d;
        }}

        /*
        Overall assessment population and NOT ASSESSED remain neutral
        because neither state independently indicates control failure.
        */
        .metric-neutral,
        .metric-not-assessed {{
            border-left: 4px solid #66788a;
        }}

        /* ---------- Control Results ---------- */

        /*
        Stack control results vertically so each control reads as a
        discrete assurance result rather than a dashboard tile.
        */
        .control-results {{
            display: grid;
            gap: 18px;
        }}

        .control-card {{
            padding: 22px 24px;
            background: #ffffff;
            border: 1px solid #dfe4e8;
            border-left: 4px solid #66788a;
            border-radius: 8px;
        }}

        /*
        The left border provides a quick visual indication of the
        control result without overwhelming the report with color.
        */
        .control-fail {{
            border-left-color: #b54747;
        }}

        .control-pass {{
            border-left-color: #2f7d5a;
        }}

        .control-not-assessed {{
            border-left-color: #66788a;
        }}

        /* ---------- Control Card Header ---------- */

        .control-card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            margin-bottom: 12px;
        }}

        .control-card-header h3 {{
            margin: 0;
            color: #17324d;
            font-size: 19px;
            font-weight: 700;
        }}

        .control-status {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* ---------- Result and Severity Badges ---------- */

        .result-badge,
        .severity-badge {{
            display: inline-block;
            padding: 5px 9px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.4px;
            line-height: 1;
        }}

        .result-pass {{
            background: #e7f4ec;
            color: #246746;
        }}

        .result-fail {{
            background: #f8e8e8;
            color: #983d3d;
        }}

        .result-not-assessed {{
            background: #edf0f2;
            color: #596b7b;
        }}

        .severity-high {{
            background: #f8ede7;
            color: #9a492e;
        }}

        .severity-critical {{
            background: #f5e3e3;
            color: #842929;
        }}

        /*
        PASS and NOT ASSESSED controls may have no active risk
        severity. N/A is therefore displayed as a neutral state.
        */
        .severity-none {{
            background: #edf0f2;
            color: #687783;
        }}

        /* ---------- Control Requirement ---------- */

        .control-requirement {{
            margin: 0 0 18px;
            color: #364553;
            font-size: 15px;
        }}

        /* ---------- Control Metrics ---------- */

        /*
        Definition-list elements are used because each value has a
        specific management-facing label.
        */
        .control-metrics {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 10px;
            margin: 0;
        }}

        .control-metrics > div {{
            padding: 12px;
            background: #f8fafb;
            border: 1px solid #e5e9ec;
            border-radius: 6px;
        }}

        .control-metrics dt {{
            margin-bottom: 4px;
            color: #71808d;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.35px;
            text-transform: uppercase;
        }}

        .control-metrics dd {{
            margin: 0;
            color: #24303d;
            font-size: 15px;
            font-weight: 650;
        }}

        /* ---------- Visual Analysis ---------- */

        .visual-analysis {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 18px;
        }}

        .visual-card {{
            padding: 24px;
            background: #ffffff;
            border: 1px solid #dfe4e8;
            border-radius: 8px;
        }}

        .visual-header {{
            margin-bottom: 20px;
        }}

        .visual-header h3 {{
            margin: 0 0 4px;
            color: #17324d;
            font-size: 18px;
            font-weight: 700;
        }}

        .visual-header p {{
            margin: 0;
            color: #71808d;
            font-size: 13px;
        }}

        /*
        The evidence comparison contains one row per control, so it spans
        the full report width beneath the two summary visualizations.
        */
        .visual-card-wide {{
            grid-column: 1 / -1;
        }}

        /* ---------- Control Outcome Bar ---------- */

        /*
        The stacked bar represents the proportion of PASS, FAIL,
        and NOT ASSESSED control outcomes.
        */
        .outcome-bar {{
            display: flex;
            width: 100%;
            height: 24px;
            overflow: hidden;
            background: #edf0f2;
            border-radius: 6px;
        }}

        .outcome-segment {{
            height: 100%;
        }}

        .outcome-pass {{
            background: #2f7d5a;
        }}

        .outcome-fail {{
            background: #b54747;
        }}

        .outcome-not-assessed {{
            background: #7a8996;
        }}

        /* ---------- Control Outcome Legend ---------- */

        .outcome-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            margin-top: 16px;
        }}

        .outcome-legend > div {{
            display: flex;
            align-items: center;
            gap: 7px;
            color: #53616e;
            font-size: 13px;
        }}

        .outcome-legend strong {{
            margin-left: 2px;
            color: #24303d;
        }}

        .legend-marker {{
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }}

        .legend-pass {{
            background: #2f7d5a;
        }}

        .legend-fail {{
            background: #b54747;
        }}

        .legend-not-assessed {{
            background: #7a8996;
        }}

        /* ---------- Finding Severity ---------- */

        /*
        Severity is visualized independently from control outcome.
        Only findings with active risk are represented here.
        */
        .severity-bar {{
            display: flex;
            width: 100%;
            height: 24px;
            overflow: hidden;
            background: #edf0f2;
            border-radius: 6px;
        }}

        .severity-segment {{
            height: 100%;
        }}

        .severity-bar-high {{
            background: #b85c38;
        }}

        .severity-bar-critical {{
            background: #8f2d2d;
        }}

        .severity-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            margin-top: 16px;
        }}

        .severity-legend > div {{
            display: flex;
            align-items: center;
            gap: 7px;
            color: #53616e;
            font-size: 13px;
        }}

        .severity-legend strong {{
            margin-left: 2px;
            color: #24303d;
        }}

        .legend-high {{
            background: #b85c38;
        }}

        .legend-critical {{
            background: #8f2d2d;
        }}

        /* ---------- Exceptions vs. Evidence Issues ---------- */

        .comparison-chart {{
            display: grid;
            gap: 16px;
        }}

        .comparison-row {{
            display: grid;
            grid-template-columns: 80px 1fr 1fr;
            gap: 18px;
            align-items: center;
        }}

        .comparison-control {{
            color: #17324d;
            font-size: 13px;
            font-weight: 700;
        }}

        .comparison-measure {{
            display: grid;
            grid-template-columns: 95px 1fr 24px;
            gap: 10px;
            align-items: center;
        }}

        .comparison-label {{
            color: #65717d;
            font-size: 11px;
            font-weight: 600;
        }}

        .comparison-track {{
            height: 12px;
            overflow: hidden;
            background: #edf0f2;
            border-radius: 4px;
        }}

        .comparison-bar {{
            height: 100%;
            border-radius: 4px;
        }}

        /*
        Red represents confirmed control exceptions.
        Amber represents evidence-quality issues.
        These are intentionally distinct concepts.
        */
        .comparison-exception {{
            background: #b54747;
        }}

        .comparison-evidence {{
            background: #c58a2b;
        }}

        .comparison-measure strong {{
            color: #24303d;
            font-size: 12px;
            text-align: right;
        }}

        /* ---------- Management Findings ---------- */

        /*
        Remediation findings are stacked vertically because each
        represents a discrete management action.
        */
        .management-findings {{
            display: grid;
            gap: 18px;
        }}

        .finding-card {{
            padding: 24px;
            background: #ffffff;
            border: 1px solid #dfe4e8;
            border-left: 4px solid #b85c38;
            border-radius: 8px;
        }}

        /* ---------- Finding Header ---------- */

        .finding-card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            padding-bottom: 14px;
            margin-bottom: 18px;
            border-bottom: 1px solid #e5e9ec;
        }}

        .finding-card-header h3 {{
            margin: 0;
            color: #17324d;
            font-size: 19px;
            font-weight: 700;
        }}

        /* ---------- Finding Content ---------- */

        .finding-content {{
            display: grid;
            gap: 18px;
        }}

        .finding-detail h4 {{
            margin: 0 0 5px;
            color: #65717d;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.4px;
            text-transform: uppercase;
        }}

        .finding-detail p {{
            margin: 0;
            color: #364553;
            font-size: 14px;
            line-height: 1.6;
        }}

        /*
        Recommendations receive a subtle background treatment so
        management can quickly distinguish the required action from
        the description of the control deficiency.
        */
        .finding-detail:last-child {{
            padding: 14px 16px;
            background: #f7f9fa;
            border-radius: 6px;
        }}

        .finding-detail:last-child h4 {{
            color: #17324d;
        }}

        /* ---------- Responsive Layout ---------- */

        /*
        Reduce the executive-summary grid to two columns on
        medium-width displays.
        */
        @media (max-width: 900px) {{
            .metrics {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .control-metrics {{
                grid-template-columns: repeat(3, 1fr);
            }}

            .visual-analysis {{
                grid-template-columns: 1fr;
            }}
        }}

        /*
        Use a single-column layout and tighter document margins on
        smaller screens.
        */
        @media (max-width: 560px) {{
            main {{
                width: calc(100% - 24px);
                margin: 12px auto;
                padding: 24px;
            }}

            .metrics {{
                grid-template-columns: 1fr;
            }}

            .control-card-header {{
                align-items: flex-start;
                flex-direction: column;
            }}

            .control-metrics {{
                grid-template-columns: repeat(2, 1fr);
            }}

            finding-card-header {{
                align-items: flex-start;
                flex-direction: column;
            }}

            .comparison-row {{
                grid-template-columns: 1fr;
                gap: 8px;
            }}

            .comparison-measure {{
                grid-template-columns: 90px 1fr 24px;
            }}

            .assessment-context {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>

<body>
    <main>
        <header>
            <h1>Control Assurance Engine</h1>
            <h2>Northstar BuildCo — Management Assessment Report</h2>

            <div class="assessment-context">
                <div>
                    <span>Assessment Date</span>
                    <strong>{assessment_date or 'Not specified'}</strong>
                </div>

                <div>
                    <span>Assessment Scope</span>
                    <strong>{assessment_scope or 'Not specified'}</strong>
                </div>

                <div>
                    <span>Framework Alignment</span>
                    <strong>{framework_alignment or 'Not specified'}</strong>
                </div>
            </div>
        </header>

        <section>
            <h2>Executive Summary</h2>

            <div class="metrics">

            <!-- Overall number of controls evaluated. -->
            <div class="metric metric-neutral">
                <span class="metric-value">
                    {summary['controls_assessed']}
                </span>
                <span class="metric-label">Controls Evaluated</span>
            </div>

            <!-- Controls that satisfied their defined requirements. -->
            <div class="metric metric-passed">
                <span class="metric-value">
                    {summary['passed']}
                </span>
                <span class="metric-label">Passed</span>
            </div>

            <!-- Controls with confirmed exceptions. -->
            <div class="metric metric-failed">
                <span class="metric-value">
                    {summary['failed']}
                </span>
                <span class="metric-label">Failed</span>
            </div>

            <!-- Controls that could not be assessed from available evidence. -->
            <div class="metric metric-not-assessed">
                <span class="metric-value">
                    {summary['not_assessed']}
                </span>
                <span class="metric-label">Not Assessed</span>
            </div>

            <!-- Confirmed exceptions across all evaluated controls. -->
            <div class="metric metric-exceptions">
                <span class="metric-value">
                    {summary['total_exceptions']}
                </span>
                <span class="metric-label">Total Exceptions</span>
            </div>

            <!-- Evidence-quality issues kept separate from control failures. -->
            <div class="metric metric-evidence">
                <span class="metric-value">
                    {summary['evidence_issues']}
                </span>
                <span class="metric-label">Evidence Issues</span>
            </div>

            <!-- Failed controls rated High severity. -->
            <div class="metric metric-high">
                <span class="metric-value">
                    {summary['high_findings']}
                </span>
                <span class="metric-label">High Findings</span>
            </div>

            <!-- Failed controls rated Critical severity. -->
            <div class="metric metric-critical">
                <span class="metric-value">
                    {summary['critical_findings']}
                </span>
                <span class="metric-label">Critical Findings</span>
            </div>

        </div>
        </section>

        <section>
            <h2>Visual Analysis</h2>

            <div class="visual-analysis">
                {format_html_control_outcomes(summary)}
                {format_html_finding_severity(summary)}
                {format_html_evidence_comparison(findings)}
            </div>
        </section>

        <section>
            <h2>Control Results</h2>

            <div class="control-results">
                {format_html_control_results(findings)}
            </div>
        </section>

        <section>
            <h2>Findings Requiring Remediation</h2>

            <div class="management-findings">
                {format_html_management_findings(management_findings)}
            </div>
        </section>

    </main>
</body>
</html>
"""