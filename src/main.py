from pathlib import Path

# Import the evidence loaders responsible for reading and validating
# Northstar's user-account and endpoint evidence.
from src.evidence import load_user_evidence, load_device_evidence

# Import the control-assessment functions used by the engine.
from src.controls import (
    assess_iam_01,
    assess_iam_02,
    assess_iam_03,
    assess_end_01,
    assess_end_02
)

# Import the reporting function that converts assessment results
# into a structured GRC control finding.
from src.reporting import (
    build_control_finding,
    build_findings_dataframe,
    export_findings_csv,
    format_control_finding
)

# Import the centralized control metadata catalog.
from src.control_catalog import CONTROL_CATALOG


# Define the location of Northstar's evidence files.
#
# Path() provides a clean and portable way to work with filesystem paths.
USER_EVIDENCE_FILE = Path('data/users.csv')
DEVICE_EVIDENCE_FILE = Path('data/devices.csv')

# Define the location for the consolidated control-findings report.
CONTROL_FINDINGS_FILE = Path('output/control_findings.csv')


def main():
    """
    Run the Control Assurance Engine against Northstar's user evidence.
    """

    # ------------------------------------------------------------------
    # EVIDENCE INGESTION
    # ------------------------------------------------------------------

    # Load and validate Northstar's endpoint evidence.
    #
    # Before returning the DataFrame, load_user_evidence() verifies that:
    # - all required columns exist
    # - Boolean fields contain valid values
    users = load_user_evidence(USER_EVIDENCE_FILE)

    # Device evidence is maintained separately from user evidence because
    # endpoint controls operate against a different assessment population.
    devices = load_device_evidence(DEVICE_EVIDENCE_FILE)



    # ------------------------------------------------------------------
    # IAM-01 ASSESSMENT
    # ------------------------------------------------------------------

    # Assess IAM-01:
    # All active user accounts must have MFA enabled.
    #
    # The control returns:
    # - confirmed control exceptions
    # - evidence-quality issues
    # - the assessable control population
    iam_01_exceptions, iam_01_evidence_issues, iam_01_population = (
        assess_iam_01(users)
    )

    # Retrieve IAM-01 metadata from the centralized control catalog.
    iam_01_control = CONTROL_CATALOG['IAM-01']

    # Build the structured finding using the catalog metadata and
    # the assessment results produced by the IAM-01 control logic.
    iam_01_finding = build_control_finding(
        control_id=iam_01_control['control_id'],
        requirement=iam_01_control['requirement'],
        assessable_population=iam_01_population,
        exceptions=iam_01_exceptions,
        evidence_issues=iam_01_evidence_issues
    )



    # ------------------------------------------------------------------
    # IAM-02 ASSESSMENT
    # ------------------------------------------------------------------

    # Assess IAM-02:
    # Terminated users must have their accounts disabled.
    #
    # IAM-02 uses the same validated user evidence but applies
    # a different control requirement and scope.
    iam_02_exceptions, iam_02_evidence_issues, iam_02_population = (
        assess_iam_02(users)
    )

    # Retrieve IAM-02 metadata from the centralized control catalog.
    iam_02_control = CONTROL_CATALOG['IAM-02']

    # Build the structured finding using the catalog metadata and
    # the assessment results produced by the IAM-02 control logic.
    iam_02_finding = build_control_finding(
        control_id=iam_02_control['control_id'],
        requirement=iam_02_control['requirement'],
        assessable_population=iam_02_population,
        exceptions=iam_02_exceptions,
        evidence_issues=iam_02_evidence_issues
    )



    # ------------------------------------------------------------------
    # IAM-03 ASSESSMENT
    # ------------------------------------------------------------------

    # Assess IAM-03:
    # Administrative privileges must be limited to approved accounts.
    #
    # IAM-03 evaluates accounts with administrative privileges and
    # determines whether those privileges have documented approval.
    iam_03_exceptions, iam_03_evidence_issues, iam_03_population = (
        assess_iam_03(users)
    )

    # Retrieve IAM-03 metadata from the centralized control catalog.
    iam_03_control = CONTROL_CATALOG['IAM-03']

    # Build the structured finding using the catalog metadata and
    # the assessment results produced by the IAM-03 control logic.
    iam_03_finding = build_control_finding(
        control_id=iam_03_control['control_id'],
        requirement=iam_03_control['requirement'],
        assessable_population=iam_03_population,
        exceptions=iam_03_exceptions,
        evidence_issues=iam_03_evidence_issues
    )



    # ------------------------------------------------------------------
    # END-01 ASSESSMENT
    # ------------------------------------------------------------------

    # Assess END-01:
    # Company-managed endpoints must use disk encryption.
    #
    # The control evaluates company-managed devices and determines
    # whether full-disk encryption is enabled.
    end_01_exceptions, end_01_evidence_issues, end_01_population = (
        assess_end_01(devices)
    )

    # Retrieve END-01 metadata from the centralized control catalog.
    end_01_control = CONTROL_CATALOG['END-01']

    # Build the structured finding using the catalog metadata and
    # the assessment results produced by the END-01 control logic.
    end_01_finding = build_control_finding(
        control_id=end_01_control['control_id'],
        requirement=end_01_control['requirement'],
        assessable_population=end_01_population,
        exceptions=end_01_exceptions,
       evidence_issues=end_01_evidence_issues,
        identifier_column='device_id'
    )



    # ------------------------------------------------------------------
    # END-02 ASSESSMENT
    # ------------------------------------------------------------------

    # Assess END-02:
    # Company-managed endpoints must have endpoint protection enabled.
    #
    # Only company-managed devices with known endpoint-protection
    # status are included in the assessable population.
    end_02_exceptions, end_02_evidence_issues, end_02_population = (
        assess_end_02(devices)
    )

    # Retrieve END-02 metadata from the centralized control catalog.
    end_02_control = CONTROL_CATALOG['END-02']

    # Build the structured finding using the catalog metadata and
    # the assessment results produced by the END-02 control logic.
    end_02_finding = build_control_finding(
       control_id=end_02_control['control_id'],
      requirement=end_02_control['requirement'],
      assessable_population=end_02_population,
      exceptions=end_02_exceptions,
      evidence_issues=end_02_evidence_issues,
      identifier_column='device_id'
    )



    # ============================================================
    # CONSOLIDATED FINDINGS EXPORT
    # ============================================================

#        Combine all structured control findings into a single collection.
#
    # Keeping the findings together allows the reporting layer to
    # convert the complete assessment into one tabular report.
    all_findings = [
        iam_01_finding,
        iam_02_finding,
        iam_03_finding,
        end_01_finding,
        end_02_finding
    ]

    # Convert the structured findings into a DataFrame suitable
    # for reporting and export.
    findings_dataframe = build_findings_dataframe(all_findings)

    # Export the consolidated findings to the project's output directory.
    export_findings_csv(
        findings_dataframe,
        CONTROL_FINDINGS_FILE
    )



    # ------------------------------------------------------------------
    # IAM-01 OUTPUT
    # ------------------------------------------------------------------

    # Display confirmed IAM-01 control exceptions.
    print('\n## IAM-01 Control Exceptions')
    print('---------------------------')

    if iam_01_exceptions.empty:
        print('No control exceptions identified.')
    else:
        print(iam_01_exceptions.to_string(index = False))

    # Display IAM-01 evidence-quality issues separately.
    #
    # This prevents incomplete evidence from being incorrectly
    # reported as a confirmed control failure.
    print('\n## IAM-01 Evidence Issues')
    print('------------------------')

    if iam_01_evidence_issues.empty:
        print('No evidence issues identified.')
    else:
        print(iam_01_evidence_issues.to_string(index = False))

    # Display the summarized IAM-01 control finding.
    print('\n## IAM-01 Control Finding')
    print('------------------------')

    # Format and display the structured IAM-01 finding.
    print(
        format_control_finding(
            iam_01_finding,
            iam_01_control['entity_label']
        )
    )



    # ------------------------------------------------------------------
    # IAM-02 OUTPUT
    # ------------------------------------------------------------------

    # Display confirmed IAM-02 control exceptions.
    print('\n## IAM-02 Control Exceptions')
    print('----------------------------')

    if iam_02_exceptions.empty:
        print('No control exceptions identified.')
    else:
        print(iam_02_exceptions.to_string(index = False))

    # Display IAM-02 evidence-quality issues separately.
    print('\n## IAM-02 Evidence Issues')
    print('-------------------------')

    if iam_02_evidence_issues.empty:
        print('No evidence issues identified.')
    else:
        print(iam_02_evidence_issues.to_string(index = False))

    # Display the summarized IAM-02 control finding.
    print('\n## IAM-02 Control Finding')
    print('-------------------------')

    # Format and display the structured IAM-02 finding.
    print(
        format_control_finding(
            iam_02_finding,
            iam_02_control['entity_label']
        )
    )



    # ------------------------------------------------------------------
    # IAM-03 OUTPUT
    # ------------------------------------------------------------------

    # Display confirmed IAM-03 control exceptions.
    print('\n## IAM-03 Control Exceptions')
    print('----------------------------')

    if iam_03_exceptions.empty:
        print('No control exceptions identified.')
    else:
        print(iam_03_exceptions.to_string(index = False))

    # Display IAM-03 evidence-quality issues separately.
    print('\n## IAM-03 Evidence Issues')
    print('-------------------------')

    if iam_03_evidence_issues.empty:
        print('No evidence issues identified.')
    else:
        print(iam_03_evidence_issues.to_string(index = False))

    # Display the summarized IAM-03 control finding.
    print('\n## IAM-03 Control Finding')
    print('-------------------------')

    # Format and display the structured IAM-03 finding.
    print(
        format_control_finding(
            iam_03_finding,
            iam_03_control['entity_label']
        )
    )



    # ------------------------------------------------------------------
    # END-01 OUTPUT
    # ------------------------------------------------------------------

    # Display the raw END-01 assessment results.
    #
    # These are useful during development because they let us inspect
    # exactly which endpoint records produced each result.
    print('\n## END-01 Control Exceptions')
    print('----------------------------')
    print(end_01_exceptions)

    print('\n## END-01 Control Evidence Issues')
    print('---------------------------------')
    print(end_01_evidence_issues)

    # Display the structured END-01 finding in a readable format
    # consistent with the IAM control findings.
    print('\n## END-01 Control Finding')
    print('-------------------------')
    
    # Format and display the structured END-01 finding.
    print(
        format_control_finding(
            end_01_finding,
            end_01_control['entity_label']
        )
    )



    # ------------------------------------------------------------------
    # END-02 OUTPUT
    # ------------------------------------------------------------------

    # Display confirmed END-02 control exceptions.
    print('\n## END-02 Control Exceptions')
    print('----------------------------')

    if end_02_exceptions.empty:
        print('No control exceptions identified.')
    else:
        print(end_02_exceptions)

    # Display END-02 evidence-quality issues separately from
    # confirmed control exceptions.
    print('\n## END-02 Evidence Issues')
    print('-------------------------')

    if end_02_evidence_issues.empty:
        print('No evidence issues identified.')
    else:
        print(end_02_evidence_issues)

    # Display the structured END-02 finding.
    print('\n## END-02 Control Finding')
    print('-------------------------')

    # Format and display the structured END-02 finding.
    print(
        format_control_finding(
            end_02_finding,
            end_02_control['entity_label']
        )
    )



# Run main() only when this module is executed directly.
#
# This prevents the assessment from automatically running if
# src.main is imported by another Python module in the future.
if __name__ == '__main__':
    main()