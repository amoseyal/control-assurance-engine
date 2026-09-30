import pandas as pd



# ============================================================
# STRUCTURED CONTROL FINDING BUILDER
# ============================================================

def build_control_finding(
        control_id,
        requirement,
        assessable_population,
        exceptions,
        evidence_issues,
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

    # Build one structured finding that can later be displayed,
    # exported, or incorporated into a larger assessment report.
    finding = {
        'control_id': control_id,
        'requirement': requirement,
        'result': result,
        'population_tested': population_tested,
        'exception_count': exception_count,
        'exception_rate': exception_rate,
        'affected_entities': affected_entities,
        'evidence_issue_count': len(evidence_issues)
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
        f"Evidence Issues: {finding['evidence_issue_count']}"
    ]

    # Join the individual fields into one multi-line string.
    #
    # The function returns the text rather than printing it
    # directly. This keeps reporting logic reusable for future
    # console output, text files, or other report formats.
    return '\n'.join(lines)



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