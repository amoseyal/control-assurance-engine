from html import escape

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

def escape_html(value):
    """
    Escape a value for safe insertion into HTML text or
    quoted HTML attributes.

    Converts the supplied value to a string and escapes
    HTML-sensitive characters, including ampersands,
    angle brackets, and quotation marks.

    Args:
        value:
            Value to be inserted into generated HTML.

    Returns:
        str:
            HTML-escaped string safe for insertion into
            HTML text or quoted attribute values.
    """
    return escape(str(value), quote=True)



def render_html_icon(name, size=18):
    """
    Return a self-contained SVG icon for the HTML report.

    Icons use currentColor so their appearance can be
    controlled through CSS. Unknown names are rejected
    rather than inserted into HTML.
    """
    paths = {
        'shield-check': (
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
            '<path d="m9 12 2 2 4-4"/>'
        ),
        'dashboard': (
            '<rect x="3" y="3" width="7" height="9" rx="1"/>'
            '<rect x="14" y="3" width="7" height="5" rx="1"/>'
            '<rect x="14" y="12" width="7" height="9" rx="1"/>'
            '<rect x="3" y="16" width="7" height="5" rx="1"/>'
        ),
        'chart': (
            '<path d="M3 3v18h18"/>'
            '<path d="M7 16v-4"/>'
            '<path d="M12 16V8"/>'
            '<path d="M17 16V5"/>'
        ),
        'clipboard-check': (
            '<rect x="5" y="4" width="14" height="18" rx="2"/>'
            '<path d="M9 4.5h6"/>'
            '<path d="m9 14 2 2 4-4"/>'
        ),
        'alert': (
            '<path d="m12 3 10 18H2L12 3z"/>'
            '<path d="M12 9v5"/>'
            '<path d="M12 18h.01"/>'
        ),
        'check': (
            '<circle cx="12" cy="12" r="9"/>'
            '<path d="m8 12 3 3 5-6"/>'
        ),
        'x-circle': (
            '<circle cx="12" cy="12" r="9"/>'
            '<path d="m9 9 6 6m0-6-6 6"/>'
        ),
        'file-warning': (
            '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
            '<path d="M14 2v6h6"/>'
            '<path d="M12 12v4"/>'
            '<path d="M12 19h.01"/>'
        ),
    }

    if name not in paths:
        raise ValueError(f'Unsupported report icon: {name}')

    if not isinstance(size, int) or not 12 <= size <= 48:
        raise ValueError('Icon size must be an integer between 12 and 48')

    return (
        f'<svg class="report-icon" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="1.8" '
        f'stroke-linecap="round" stroke-linejoin="round" '
        f'aria-hidden="true" focusable="false">'
        f'{paths[name]}'
        '</svg>'
    )


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
        severity = finding.get("severity") or "N/A"
        risk_score = finding.get("risk_score")

        # Restrict CSS classes to known assessment values.
        # Unexpected values use a neutral class rather than
        # being inserted directly into HTML attributes.
        result_classes = {
            "PASS": "pass",
            "FAIL": "fail",
            "NOT ASSESSED": "not-assessed",
        }

        severity_classes = {"HIGH": "high", "CRITICAL": "critical"}

        result_class = result_classes.get(str(finding["result"]).upper(), "unknown")

        # Map each control outcome to an appropriate SVG icon.
        # Unknown outcomes receive a neutral icon.
        result_icons = {
            'PASS': 'check',
            'FAIL': 'x-circle',
            'NOT ASSESSED': 'dashboard',
        }

        # Select and render the icon for this control.
        result_icon_name = result_icons.get(
            str(finding['result']).upper(),
            'dashboard'
        )

        result_icon = render_html_icon(result_icon_name, 15)

        severity_class = severity_classes.get(
            str(finding.get("severity")).upper(), "none"
        )

        # Select an SVG icon for active finding severities.
        # Controls without an assigned severity receive no icon.
        severity_icons = {
            'HIGH': 'alert',
            'CRITICAL': 'alert',
        }

        severity_icon_name = severity_icons.get(
            str(finding.get('severity')).upper()
        )

        severity_icon = (
            render_html_icon(severity_icon_name, 14)
            if severity_icon_name
            else ''
        )

        if risk_score is None:
            risk_score_text = "N/A"
        else:
            risk_score_text = str(risk_score)

        # Build one HTML card using values already calculated by
        # the control-assessment and risk-evaluation layers.
        card = f"""
            <article class="control-card control-{result_class}">
                <div class="control-card-header">
                    <h3>{escape_html(finding['control_id'])}</h3>

                    <div class="control-status">
                        <span class="result-badge result-{result_class}">
                            {result_icon}
                            {escape_html(finding['result'])}
                        </span>

                        <span class="severity-badge severity-{severity_class}">
                            {severity_icon}
                            {escape_html(severity)}
                        </span>
                    </div>
                </div>

                <p class="control-requirement">
                    {escape_html(finding['requirement'])}
                </p>

                <dl class="control-metrics">
                    <div>
                        <dt>NIST CSF</dt>
                        <dd>{escape_html(finding['nist_csf_subcategory'])}</dd>
                    </div>

                    <div>
                        <dt>Population Tested</dt>
                        <dd>{escape_html(finding['population_tested'])}</dd>
                    </div>

                    <div>
                        <dt>Exceptions</dt>
                        <dd>{escape_html(finding['exception_count'])}</dd>
                    </div>

                    <div>
                        <dt>Exception Rate</dt>
                        <dd>{escape_html(finding['exception_rate'])}%</dd>
                    </div>

                    <div>
                        <dt>Evidence Issues</dt>
                        <dd>{escape_html(finding['evidence_issue_count'])}</dd>
                    </div>

                    <div>
                        <dt>Risk Score</dt>
                        <dd>{escape_html(risk_score_text)}</dd>
                    </div>
                </dl>
            </article>
        """

        control_cards.append(card)

    # Combine all control cards into one HTML block.
    return "\n".join(control_cards)


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
        # Escape each affected entity before combining them.
        # This prevents entity names from introducing HTML markup.
        affected_entities = ", ".join(
            escape_html(entity) for entity in finding["affected_entities"]
        )

        # Restrict severity CSS classes to known values.
        severity_classes = {"HIGH": "high", "CRITICAL": "critical"}

        # Use the finding's severity for the management report.
        severity = finding['severity']

        severity_class = severity_classes.get(str(finding["severity"]).upper(), "none")

        # Display severity icons only for active risk findings.
        severity_icons = {
            'HIGH': 'alert',
            'CRITICAL': 'alert',
        }

        severity_icon_name = severity_icons.get(
            str(finding.get('severity')).upper()
        )

        severity_icon = (
            render_html_icon(severity_icon_name, 14)
            if severity_icon_name
            else ''
        )

        card = f"""
            <article class="finding-card">
                <div class="finding-card-header">
                    <h3>{escape_html(finding['control_id'])}</h3>

                    <span class="severity-badge severity-{severity_class}">
                        {severity_icon}
                        {escape_html(severity)}
                    </span>
                </div>

                <div class="finding-content">
                    <div class="finding-detail">
                        <h4>Finding</h4>
                        <p>{escape_html(finding['finding_description'])}</p>
                    </div>

                    <div class="finding-detail">
                        <h4>Affected</h4>
                        <p>{affected_entities}</p>
                    </div>

                    <div class="finding-detail">
                        <h4>Recommendation</h4>
                        <p>{escape_html(finding['recommendation'])}</p>
                    </div>
                </div>
            </article>
        """

        finding_cards.append(card)

    return "\n".join(finding_cards)


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
            max(finding["exception_count"], finding["evidence_issue_count"])
            for finding in findings
        ),
        default=0,
    )

    for finding in findings:
        exception_count = finding["exception_count"]
        evidence_issue_count = finding["evidence_issue_count"]

        # Convert counts into relative bar widths for presentation.
        # The displayed numbers remain the authoritative values.
        if max_count == 0:
            exception_percent = 0
            evidence_percent = 0
        else:
            exception_percent = exception_count / max_count * 100
            evidence_percent = evidence_issue_count / max_count * 100

        row = f"""
            <div class="comparison-row">
                <div class="comparison-control">
                    {escape_html(finding['control_id'])}
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
    findings, assessment_date=None, assessment_scope=None, framework_alignment=None
):
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

        /*
        Dark dashboard foundation.
        The page background contrasts with the report container,
        while maintaining readable text and restrained borders.
        */
        body {{
            margin: 0;
            background: #0b1120;
            color: #e2e8f0;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Arial,
                sans-serif;
            line-height: 1.5;
        }}

        /*
        Main dashboard container.
        Preserve the existing dimensions and spacing while
        replacing the light document surface with a dark panel.
        */
        main {{
            width: min(1180px, calc(100% - 48px));
            margin: 40px auto;
            background: #111827;
            border: 1px solid #263449;
            border-radius: 12px;
            padding: 48px;
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.24);
        }}

        /* ---------- Report Icons ---------- */

        /*
        Keep inline SVG icons aligned with report headings.
        Icons inherit their color from the surrounding text.
        */
        .report-icon {{
            display: inline-block;
            flex-shrink: 0;
            vertical-align: -0.18em;
        }}

        header h1 .report-icon,
        section > h2 .report-icon {{
            margin-right: 8px;
        }}

        /* ---------- Report Header ---------- */

        /*
        Establish a clear hierarchy between the report title,
        organization, and assessment metadata.
        */
        header {{
            padding-bottom: 28px;
            margin-bottom: 36px;
            border-bottom: 1px solid #334155;
        }}

        header h1 {{
            margin: 0;
            color: #f8fafc;
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        header h2 {{
            margin: 8px 0 0;
            color: #94a3b8;
            font-size: 18px;
            font-weight: 500;
        }}

        /* ---------- Assessment Context ---------- */

        /*
        Present assessment metadata in a responsive grid,
        separating labels from their corresponding values.
        */
        .assessment-context {{
            display: grid;
            grid-template-columns: 1fr 2fr 1.5fr;
            gap: 18px;
            margin-top: 24px;
            padding-top: 20px;
            border-top: 1px solid #263449;
        }}

        .assessment-context > div {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .assessment-context span {{
            color: #94a3b8;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.4px;
            text-transform: uppercase;
        }}

        .assessment-context strong {{
            color: #e2e8f0;
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
            color: #f1f5f9;
            font-size: 22px;
            font-weight: 650;
        }}

        /* ---------- Executive Summary Metrics ---------- */

        /*
        Display eight executive metrics in a four-column grid.
        Responsive breakpoints are handled later in the stylesheet.
        */
        .metrics {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
        }}

        /*
        Use a consistent dark surface for every metric.
        Semantic meaning is conveyed through the left border
        and metric value rather than different card backgrounds.
        */
        .metric {{
            min-height: 110px;
            padding: 20px;
            background: #1e293b;
            border: 1px solid #334155;
            border-left: 4px solid #64748b;
            border-radius: 10px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}

        .metric-value {{
            display: block;
            margin-bottom: 8px;
            color: #f8fafc;
            font-size: 30px;
            font-weight: 700;
            line-height: 1.1;
        }}

        .metric-label {{
            display: block;
            color: #94a3b8;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.4px;
            text-transform: uppercase;
        }}

        /* ---------- Semantic Metric States ---------- */

        /*
        Passed controls: successful assurance outcomes.
        */
        .metric-passed {{
            border-left-color: #34d399;
        }}

        .metric-passed .metric-value {{
            color: #6ee7b7;
        }}

        /*
        Failed controls: confirmed control failures.
        */
        .metric-failed {{
            border-left-color: #f87171;
        }}

        .metric-failed .metric-value {{
            color: #fca5a5;
        }}

        /*
        Evidence issues: assessment-quality concerns,
        distinct from confirmed control failures.
        */
        .metric-evidence {{
            border-left-color: #fbbf24;
        }}

        .metric-evidence .metric-value {{
            color: #fcd34d;
        }}

        /*
        Exceptions: aggregate volume, not a severity rating.
        */
        .metric-exceptions {{
            border-left-color: #38bdf8;
        }}

        .metric-exceptions .metric-value {{
            color: #7dd3fc;
        }}

        /*
        High-severity findings: elevated risk.
        */
        .metric-high {{
            border-left-color: #fb923c;
        }}

        .metric-high .metric-value {{
            color: #fdba74;
        }}

        /*
        Critical findings: strongest severity signal.
        */
        .metric-critical {{
            border-left-color: #e879f9;
        }}

        .metric-critical .metric-value {{
            color: #f0abfc;
        }}

        /*
        Neutral states: assessment population and controls
        that could not be assessed.
        */
        .metric-neutral,
        .metric-not-assessed {{
            border-left-color: #64748b;
        }}

        /* ---------- Control Results ---------- */

        /*
        Display each assessed control as a separate dashboard
        panel with a clear outcome indicator.
        */
        .control-results {{
            display: grid;
            gap: 18px;
        }}

        .control-card {{
            padding: 22px 24px;
            background: #1e293b;
            border: 1px solid #334155;
            border-left: 4px solid #64748b;
            border-radius: 10px;
        }}

        /*
        Control outcome colors remain distinct from
        finding severity and evidence-quality indicators.
        */
        .control-fail {{
            border-left-color: #f87171;
        }}

        .control-pass {{
            border-left-color: #34d399;
        }}

        .control-not-assessed {{
            border-left-color: #64748b;
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
            color: #f8fafc;
            font-size: 19px;
            font-weight: 700;
        }}

        .control-status {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* ---------- Result and Severity Badges ---------- */

        /*
        Use contrasting dark badge backgrounds and readable
        foreground colors to distinguish outcome and severity.
        Align SVG icons and text consistently.
        */
        .result-badge,
        .severity-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 5px 9px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.4px;
            line-height: 1;
        }}

        .result-pass {{
            background: #064e3b;
            color: #a7f3d0;
        }}

        .result-fail {{
            background: #7f1d1d;
            color: #fecaca;
        }}

        .result-not-assessed {{
            background: #334155;
            color: #cbd5e1;
        }}

        .severity-high {{
            background: #7c2d12;
            color: #fed7aa;
        }}

        .severity-critical {{
            background: #701a75;
            color: #f5d0fe;
        }}

        /*
        Controls without an active risk rating display
        a neutral N/A severity indicator.
        */
        .severity-none {{
            background: #334155;
            color: #cbd5e1;
        }}

        /* ---------- Control Requirement ---------- */

        .control-requirement {{
            margin: 0 0 18px;
            color: #cbd5e1;
            font-size: 15px;
        }}

        /* ---------- Control Metrics ---------- */

        /*
        Preserve the six-column definition-list layout.
        Individual metrics use a slightly darker inset surface.
        */
        .control-metrics {{
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 10px;
            margin: 0;
        }}

        .control-metrics > div {{
            padding: 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
        }}

        .control-metrics dt {{
            margin-bottom: 4px;
            color: #94a3b8;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.35px;
            text-transform: uppercase;
        }}

        .control-metrics dd {{
            margin: 0;
            color: #f1f5f9;
            font-size: 15px;
            font-weight: 650;
        }}

        /* ---------- Visual Analysis ---------- */

        /*
        Arrange the two summary charts side by side.
        The evidence comparison spans the full width below.
        */
        .visual-analysis {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 18px;
        }}

        .visual-card {{
            padding: 24px;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
        }}

        .visual-header {{
            margin-bottom: 20px;
        }}

        .visual-header h3 {{
            margin: 0 0 4px;
            color: #f8fafc;
            font-size: 18px;
            font-weight: 700;
        }}

        .visual-header p {{
            margin: 0;
            color: #94a3b8;
            font-size: 13px;
        }}

        /*
        The evidence comparison spans both columns
        because it contains one row per assessed control.
        */
        .visual-card-wide {{
            grid-column: 1 / -1;
        }}

        /* ---------- Control Outcome Bar ---------- */

        .outcome-bar {{
            display: flex;
            width: 100%;
            height: 24px;
            overflow: hidden;
            background: #0f172a;
            border-radius: 6px;
        }}

        .outcome-segment {{
            height: 100%;
        }}

        .outcome-pass {{
            background: #34d399;
        }}

        .outcome-fail {{
            background: #f87171;
        }}

        .outcome-not-assessed {{
            background: #64748b;
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
            color: #cbd5e1;
            font-size: 13px;
        }}

        .outcome-legend strong {{
            margin-left: 2px;
            color: #f8fafc;
        }}

        .legend-marker {{
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }}

        .legend-pass {{
            background: #34d399;
        }}

        .legend-fail {{
            background: #f87171;
        }}

        .legend-not-assessed {{
            background: #64748b;
        }}

        /* ---------- Finding Severity ---------- */

        /*
        Severity remains separate from control outcome.
        High and Critical findings have distinct colors.
        */
        .severity-bar {{
            display: flex;
            width: 100%;
            height: 24px;
            overflow: hidden;
            background: #0f172a;
            border-radius: 6px;
        }}

        .severity-segment {{
            height: 100%;
        }}

        .severity-bar-high {{
            background: #fb923c;
        }}

        .severity-bar-critical {{
            background: #e879f9;
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
            color: #cbd5e1;
            font-size: 13px;
        }}

        .severity-legend strong {{
            margin-left: 2px;
            color: #f8fafc;
        }}

        .legend-high {{
            background: #fb923c;
        }}

        .legend-critical {{
            background: #e879f9;
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
            color: #f1f5f9;
            font-size: 13px;
            font-weight: 700;
        }}

        .comparison-measure {{
            display: grid;
            grid-template-columns: 95px minmax(0, 1fr) 24px;
            gap: 10px;
            align-items: center;
        }}

        .comparison-label {{
            color: #94a3b8;
            font-size: 11px;
            font-weight: 600;
        }}

        .comparison-track {{
            height: 12px;
            overflow: hidden;
            background: #0f172a;
            border-radius: 4px;
        }}

        .comparison-bar {{
            height: 100%;
            border-radius: 4px;
        }}

        /*
        Confirmed exceptions use red.
        Evidence-quality issues use amber to avoid
        implying that missing evidence is a control failure.
        */
        .comparison-exception {{
            background: #f87171;
        }}

        .comparison-evidence {{
            background: #fbbf24;
        }}

        .comparison-measure strong {{
            color: #f8fafc;
            font-size: 12px;
            text-align: right;
        }}

        /* ---------- Management Findings ---------- */

        /*
        Display each remediation finding as a separate panel.
        The accent border distinguishes findings from
        general control-assessment results.
        */
        .management-findings {{
            display: grid;
            gap: 18px;
        }}

        .finding-card {{
            padding: 24px;
            background: #1e293b;
            border: 1px solid #334155;
            border-left: 4px solid #fb923c;
            border-radius: 10px;
        }}

        /* ---------- Finding Header ---------- */

        .finding-card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            padding-bottom: 14px;
            margin-bottom: 18px;
            border-bottom: 1px solid #334155;
        }}

        .finding-card-header h3 {{
            margin: 0;
            color: #f8fafc;
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
            color: #94a3b8;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.4px;
            text-transform: uppercase;
        }}

        .finding-detail p {{
            margin: 0;
            color: #cbd5e1;
            font-size: 14px;
            line-height: 1.6;
        }}

        /*
        Highlight the recommended management action
        without implying an additional risk rating.
        */
        .finding-detail:last-child {{
            padding: 14px 16px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
        }}

        .finding-detail:last-child h4 {{
            color: #7dd3fc;
        }}

        /* ---------- KPI Icons ---------- */

        /*
        Display SVG icons above the metric values.
        Icons inherit their color from their metric cards.
        */
        .metric-icon {{
            display: flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            margin-bottom: 12px;
            color: inherit;
        }}

        /* ---------- KPI Icon Colors ---------- */

        /*
        Match each icon to its metric's semantic color.
        Keep control outcomes, evidence issues, and finding
        severities visually distinct.
        */

        .metric-neutral .metric-icon {{
            color: #e2e8f0;
        }}

        .metric-passed .metric-icon {{
            color: #34d399;
        }}

        .metric-failed .metric-icon {{
            color: #f87171;
        }}

        .metric-not-assessed .metric-icon {{
            color: #94a3b8;
        }}

        .metric-exceptions .metric-icon {{
            color: #38bdf8;
        }}

        .metric-evidence .metric-icon {{
            color: #fbbf24;
        }}

        .metric-high .metric-icon {{
            color: #fb923c;
        }}

        .metric-critical .metric-icon {{
            color: #e879f9;
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

            .finding-card-header {{
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
            <h1>{render_html_icon('shield-check', 28)} Control Assurance Engine</h1>
            <h2>Northstar BuildCo — Management Assessment Report</h2>

            <div class="assessment-context">
                <div>
                    <span>Assessment Date</span>
                    <strong>{escape_html(assessment_date or 'Not specified')}</strong>
                </div>

                <div>
                    <span>Assessment Scope</span>
                    <strong>{escape_html(assessment_scope or 'Not specified')}</strong>
                </div>

                <div>
                    <span>Framework Alignment</span>
                    <strong>{escape_html(framework_alignment or 'Not specified')}</strong>
                </div>
            </div>
        </header>

        <section>
            <h2>{render_html_icon('dashboard', 21)} Executive Summary</h2>

            <div class="metrics">

            <!-- Overall number of controls evaluated. -->
            <div class="metric metric-neutral">
                <span class="metric-icon">
                    {render_html_icon('clipboard-check', 20)}
                </span>
                <span class="metric-value">
                    {summary['controls_assessed']}
                </span>
                <span class="metric-label">Controls Evaluated</span>
            </div>

            <!-- Controls that satisfied their defined requirements. -->
            <div class="metric metric-passed">
                <span class="metric-icon">
                    {render_html_icon('check', 20)}
                </span>
                <span class="metric-value">
                    {summary['passed']}
                </span>
                <span class="metric-label">Passed</span>
            </div>

            <!-- Controls with confirmed exceptions. -->
            <div class="metric metric-failed">
                <span class="metric-icon">
                    {render_html_icon('x-circle', 20)}
                </span>
                <span class="metric-value">
                    {summary['failed']}
                </span>
                <span class="metric-label">Failed</span>
            </div>

            <!-- Controls that could not be assessed from available evidence. -->
            <div class="metric metric-not-assessed">
                <span class="metric-icon">
                    {render_html_icon('dashboard', 20)}
                </span>
                <span class="metric-value">
                    {summary['not_assessed']}
                </span>
                <span class="metric-label">Not Assessed</span>
            </div>

            <!-- Confirmed exceptions across all evaluated controls. -->
            <div class="metric metric-exceptions">
                <span class="metric-icon">
                    {render_html_icon('alert', 20)}
                </span>
                <span class="metric-value">
                    {summary['total_exceptions']}
                </span>
                <span class="metric-label">Total Exceptions</span>
            </div>

            <!-- Evidence-quality issues kept separate from control failures. -->
            <div class="metric metric-evidence">
                <span class="metric-icon">
                    {render_html_icon('file-warning', 20)}
                </span>
                <span class="metric-value">
                    {summary['evidence_issues']}
                </span>
                <span class="metric-label">Evidence Issues</span>
            </div>

            <!-- Failed controls rated High severity. -->
            <div class="metric metric-high">
                <span class="metric-icon">
                    {render_html_icon('alert', 20)}
                </span>
                <span class="metric-value">
                    {summary['high_findings']}
                </span>
                <span class="metric-label">High Findings</span>
            </div>

            <!-- Failed controls rated Critical severity. -->
            <div class="metric metric-critical">
                <span class="metric-icon">
                    {render_html_icon('shield-check', 20)}
                </span>
                <span class="metric-value">
                    {summary['critical_findings']}
                </span>
                <span class="metric-label">Critical Findings</span>
            </div>

        </div>
        </section>

        <section>
            <h2>{render_html_icon('chart', 21)} Visual Analysis</h2>

            <div class="visual-analysis">
                {format_html_control_outcomes(summary)}
                {format_html_finding_severity(summary)}
                {format_html_evidence_comparison(findings)}
            </div>
        </section>

        <section>
            <h2>{render_html_icon('clipboard-check', 21)} Control Results</h2>

            <div class="control-results">
                {format_html_control_results(findings)}
            </div>
        </section>

        <section>
            <h2>{render_html_icon('alert', 21)} Findings Requiring Remediation</h2>

            <div class="management-findings">
                {format_html_management_findings(management_findings)}
            </div>
        </section>

    </main>
</body>
</html>
"""
