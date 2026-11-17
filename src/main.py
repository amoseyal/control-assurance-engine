"""
Run the Control Assurance Engine command-line assessment.

Load security evidence, evaluate controls, and generate
risk findings and management reports.
"""

from datetime import datetime
from pathlib import Path

from src.control_catalog import CONTROL_CATALOG
from src.controls import (
    assess_end_01,
    assess_end_02,
    assess_iam_01,
    assess_iam_02,
    assess_iam_03,
    assess_tpr_01,
    assess_tpr_02,
)
from src.evidence import load_device_evidence, load_user_evidence, load_vendor_evidence
from src.reporting import (
    build_control_finding,
    build_executive_summary,
    build_findings_dataframe,
    build_management_findings,
    export_findings_csv,
    export_management_report,
    format_control_finding,
    format_executive_summary,
    format_html_report,
    format_management_findings,
    generate_management_report,
)

# File paths
USER_EVIDENCE_FILE = Path("data/users.csv")
DEVICE_EVIDENCE_FILE = Path("data/devices.csv")
VENDOR_EVIDENCE_FILE = Path("data/vendors.csv")
CONTROL_FINDINGS_FILE = Path("output/control_findings.csv")
MANAGEMENT_REPORT_FILE = Path("output/management_report.md")
HTML_MANAGEMENT_REPORT_FILE = Path("output/management_report.html")

# Record the date on which the assessment is executed.
# Building the string manually avoids platform-specific strftime
# directives for displaying the day without a leading zero.
today = datetime.now()

ASSESSMENT_DATE = f"{today.strftime('%B')} {today.day}, {today.year}"

ASSESSMENT_SCOPE = (
    "Identity and Access Management, Endpoint Security, and Third-Party Risk"
)

FRAMEWORK_ALIGNMENT = "NIST Cybersecurity Framework (CSF) 2.0"


def main():
    """
    Run the Control Assurance Engine against Northstar's user evidence.
    """

    # Evidence ingestion

    # Load and validate user-account evidence, including required
    # columns and Boolean field values.
    users = load_user_evidence(USER_EVIDENCE_FILE)

    # Device evidence is maintained separately from user evidence because
    # endpoint controls operate against a different assessment population.
    devices = load_device_evidence(DEVICE_EVIDENCE_FILE)

    # Vendor evidence is maintained separately because third-party
    # risk controls operate against Northstar's external vendor population.
    vendors = load_vendor_evidence(VENDOR_EVIDENCE_FILE)

    # IAM-01 assessment

    # Evaluate MFA compliance for active user accounts.
    # Separate confirmed exceptions from evidence-quality issues.
    iam_01_exceptions, iam_01_evidence_issues, iam_01_population = assess_iam_01(users)

    iam_01_control = CONTROL_CATALOG["IAM-01"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    iam_01_finding = build_control_finding(
        control_id=iam_01_control["control_id"],
        requirement=iam_01_control["requirement"],
        finding_description=iam_01_control["finding_description"],
        recommendation=iam_01_control["recommendation"],
        assessable_population=iam_01_population,
        exceptions=iam_01_exceptions,
        evidence_issues=iam_01_evidence_issues,
        nist_csf_function=iam_01_control["nist_csf_function"],
        nist_csf_category=iam_01_control["nist_csf_category"],
        nist_csf_category_name=iam_01_control["nist_csf_category_name"],
        nist_csf_subcategory=iam_01_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=iam_01_control["nist_csf_subcategory_outcome"],
        likelihood=CONTROL_CATALOG["IAM-01"]["likelihood"],
        impact=CONTROL_CATALOG["IAM-01"]["impact"],
    )

    # IAM-02 assessment

    # Evaluate whether terminated user accounts have been disabled.
    # Reuse validated user evidence with a different assessment scope.
    iam_02_exceptions, iam_02_evidence_issues, iam_02_population = assess_iam_02(users)

    iam_02_control = CONTROL_CATALOG["IAM-02"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    iam_02_finding = build_control_finding(
        control_id=iam_02_control["control_id"],
        requirement=iam_02_control["requirement"],
        finding_description=iam_02_control["finding_description"],
        recommendation=iam_02_control["recommendation"],
        assessable_population=iam_02_population,
        exceptions=iam_02_exceptions,
        evidence_issues=iam_02_evidence_issues,
        nist_csf_function=iam_02_control["nist_csf_function"],
        nist_csf_category=iam_02_control["nist_csf_category"],
        nist_csf_category_name=iam_02_control["nist_csf_category_name"],
        nist_csf_subcategory=iam_02_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=iam_02_control["nist_csf_subcategory_outcome"],
        likelihood=CONTROL_CATALOG["IAM-02"]["likelihood"],
        impact=CONTROL_CATALOG["IAM-02"]["impact"],
    )

    # IAM-03 assessment

    # Evaluate whether administrative privileges have documented approval.
    # Identify unauthorized privileges and evidence-quality issues.
    iam_03_exceptions, iam_03_evidence_issues, iam_03_population = assess_iam_03(users)

    iam_03_control = CONTROL_CATALOG["IAM-03"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    iam_03_finding = build_control_finding(
        control_id=iam_03_control["control_id"],
        requirement=iam_03_control["requirement"],
        finding_description=iam_03_control["finding_description"],
        recommendation=iam_03_control["recommendation"],
        assessable_population=iam_03_population,
        exceptions=iam_03_exceptions,
        evidence_issues=iam_03_evidence_issues,
        nist_csf_function=iam_03_control["nist_csf_function"],
        nist_csf_category=iam_03_control["nist_csf_category"],
        nist_csf_category_name=iam_03_control["nist_csf_category_name"],
        nist_csf_subcategory=iam_03_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=iam_03_control["nist_csf_subcategory_outcome"],
        likelihood=CONTROL_CATALOG["IAM-03"]["likelihood"],
        impact=CONTROL_CATALOG["IAM-03"]["impact"],
    )

    # END-01 assessment

    # Evaluate full-disk encryption compliance for company-managed devices.
    # Separate confirmed exceptions from evidence-quality issues.
    end_01_exceptions, end_01_evidence_issues, end_01_population = assess_end_01(
        devices
    )

    end_01_control = CONTROL_CATALOG["END-01"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    end_01_finding = build_control_finding(
        control_id=end_01_control["control_id"],
        requirement=end_01_control["requirement"],
        finding_description=end_01_control["finding_description"],
        recommendation=end_01_control["recommendation"],
        assessable_population=end_01_population,
        exceptions=end_01_exceptions,
        evidence_issues=end_01_evidence_issues,
        identifier_column="device_id",
        nist_csf_function=end_01_control["nist_csf_function"],
        nist_csf_category=end_01_control["nist_csf_category"],
        nist_csf_category_name=end_01_control["nist_csf_category_name"],
        nist_csf_subcategory=end_01_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=end_01_control["nist_csf_subcategory_outcome"],
        likelihood=CONTROL_CATALOG["END-01"]["likelihood"],
        impact=CONTROL_CATALOG["END-01"]["impact"],
    )

    # END-02 assessment

    # Evaluate endpoint protection compliance for company-managed devices.
    # Include only devices with known protection status in the assessable population.
    end_02_exceptions, end_02_evidence_issues, end_02_population = assess_end_02(
        devices
    )

    end_02_control = CONTROL_CATALOG["END-02"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    end_02_finding = build_control_finding(
        control_id=end_02_control["control_id"],
        requirement=end_02_control["requirement"],
        finding_description=end_02_control["finding_description"],
        recommendation=end_02_control["recommendation"],
        assessable_population=end_02_population,
        exceptions=end_02_exceptions,
        evidence_issues=end_02_evidence_issues,
        identifier_column="device_id",
        nist_csf_function=end_02_control["nist_csf_function"],
        nist_csf_category=end_02_control["nist_csf_category"],
        nist_csf_category_name=end_02_control["nist_csf_category_name"],
        nist_csf_subcategory=end_02_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=end_02_control["nist_csf_subcategory_outcome"],
        likelihood=CONTROL_CATALOG["END-02"]["likelihood"],
        impact=CONTROL_CATALOG["END-02"]["impact"],
    )

    # TPR-01 assessment

    # Evaluate whether critical vendors have completed security reviews.
    # Separate confirmed exceptions from evidence-quality issues.
    tpr_01_exceptions, tpr_01_evidence_issues, tpr_01_population = assess_tpr_01(
        vendors
    )

    tpr_01_control = CONTROL_CATALOG["TPR-01"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    tpr_01_finding = build_control_finding(
        control_id=tpr_01_control["control_id"],
        requirement=tpr_01_control["requirement"],
        finding_description=tpr_01_control["finding_description"],
        recommendation=tpr_01_control["recommendation"],
        assessable_population=tpr_01_population,
        exceptions=tpr_01_exceptions,
        evidence_issues=tpr_01_evidence_issues,
        identifier_column="vendor_id",
        nist_csf_function=tpr_01_control["nist_csf_function"],
        nist_csf_category=tpr_01_control["nist_csf_category"],
        nist_csf_category_name=tpr_01_control["nist_csf_category_name"],
        nist_csf_subcategory=tpr_01_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=tpr_01_control["nist_csf_subcategory_outcome"],
        likelihood=tpr_01_control["likelihood"],
        impact=tpr_01_control["impact"],
    )

    # TPR-02 assessment

    # Evaluate MFA compliance for vendors with privileged access.
    # Separate confirmed exceptions from evidence-quality issues.
    tpr_02_exceptions, tpr_02_evidence_issues, tpr_02_population = assess_tpr_02(
        vendors
    )

    tpr_02_control = CONTROL_CATALOG["TPR-02"]

    # Combine assessment results with catalog metadata to build
    # the structured control finding.
    tpr_02_finding = build_control_finding(
        control_id=tpr_02_control["control_id"],
        requirement=tpr_02_control["requirement"],
        finding_description=tpr_02_control["finding_description"],
        recommendation=tpr_02_control["recommendation"],
        assessable_population=tpr_02_population,
        exceptions=tpr_02_exceptions,
        evidence_issues=tpr_02_evidence_issues,
        identifier_column="vendor_id",
        nist_csf_function=tpr_02_control["nist_csf_function"],
        nist_csf_category=tpr_02_control["nist_csf_category"],
        nist_csf_category_name=tpr_02_control["nist_csf_category_name"],
        nist_csf_subcategory=tpr_02_control["nist_csf_subcategory"],
        nist_csf_subcategory_outcome=tpr_02_control["nist_csf_subcategory_outcome"],
        likelihood=tpr_02_control["likelihood"],
        impact=tpr_02_control["impact"],
    )

    # Consolidated findings and reporting

    all_findings = [
        iam_01_finding,
        iam_02_finding,
        iam_03_finding,
        end_01_finding,
        end_02_finding,
        tpr_01_finding,
        tpr_02_finding,
    ]

    executive_summary = build_executive_summary(all_findings)

    # Display the executive-level assessment summary before the
    # detailed individual control findings.
    print("\n## Executive Summary")
    print("--------------------")
    print(format_executive_summary(executive_summary))

    findings_dataframe = build_findings_dataframe(all_findings)

    export_findings_csv(findings_dataframe, CONTROL_FINDINGS_FILE)

    # Include only confirmed control failures in the remediation report.
    management_findings = build_management_findings(all_findings)

    print("\n## Findings Requiring Remediation")
    print("---------------------------------")
    print(format_management_findings(management_findings))

    management_report = generate_management_report(
        executive_summary,
        management_findings,
        assessment_date=ASSESSMENT_DATE,
        assessment_scope=ASSESSMENT_SCOPE,
        framework_alignment=FRAMEWORK_ALIGNMENT,
    )

    export_management_report(management_report, MANAGEMENT_REPORT_FILE)

    # Use the same assessment context for both report formats.
    html_management_report = format_html_report(
        all_findings,
        assessment_date=ASSESSMENT_DATE,
        assessment_scope=ASSESSMENT_SCOPE,
        framework_alignment=FRAMEWORK_ALIGNMENT,
    )

    export_management_report(html_management_report, HTML_MANAGEMENT_REPORT_FILE)

    # IAM-01 output

    print("\n## IAM-01 Control Exceptions")
    print("---------------------------")

    if iam_01_exceptions.empty:
        print("No control exceptions identified.")
    else:
        print(iam_01_exceptions.to_string(index=False))

    # Keep incomplete evidence separate from confirmed control failures.
    print("\n## IAM-01 Evidence Issues")
    print("------------------------")

    if iam_01_evidence_issues.empty:
        print("No evidence issues identified.")
    else:
        print(iam_01_evidence_issues.to_string(index=False))

    print("\n## IAM-01 Control Finding")
    print("------------------------")

    print(format_control_finding(iam_01_finding, iam_01_control["entity_label"]))

    # IAM-02 output

    print("\n## IAM-02 Control Exceptions")
    print("----------------------------")

    if iam_02_exceptions.empty:
        print("No control exceptions identified.")
    else:
        print(iam_02_exceptions.to_string(index=False))

    print("\n## IAM-02 Evidence Issues")
    print("-------------------------")

    if iam_02_evidence_issues.empty:
        print("No evidence issues identified.")
    else:
        print(iam_02_evidence_issues.to_string(index=False))

    print("\n## IAM-02 Control Finding")
    print("-------------------------")

    print(format_control_finding(iam_02_finding, iam_02_control["entity_label"]))

    # IAM-03 output

    print("\n## IAM-03 Control Exceptions")
    print("----------------------------")

    if iam_03_exceptions.empty:
        print("No control exceptions identified.")
    else:
        print(iam_03_exceptions.to_string(index=False))

    print("\n## IAM-03 Evidence Issues")
    print("-------------------------")

    if iam_03_evidence_issues.empty:
        print("No evidence issues identified.")
    else:
        print(iam_03_evidence_issues.to_string(index=False))

    print("\n## IAM-03 Control Finding")
    print("-------------------------")

    print(format_control_finding(iam_03_finding, iam_03_control["entity_label"]))

    # END-01 output

    # Display raw assessment results for troubleshooting and verification.
    print("\n## END-01 Control Exceptions")
    print("----------------------------")
    print(end_01_exceptions)

    print("\n## END-01 Control Evidence Issues")
    print("---------------------------------")
    print(end_01_evidence_issues)

    print("\n## END-01 Control Finding")
    print("-------------------------")

    print(format_control_finding(end_01_finding, end_01_control["entity_label"]))

    # END-02 output

    print("\n## END-02 Control Exceptions")
    print("----------------------------")

    if end_02_exceptions.empty:
        print("No control exceptions identified.")
    else:
        print(end_02_exceptions)

    print("\n## END-02 Evidence Issues")
    print("-------------------------")

    if end_02_evidence_issues.empty:
        print("No evidence issues identified.")
    else:
        print(end_02_evidence_issues)

    print("\n## END-02 Control Finding")
    print("-------------------------")

    print(format_control_finding(end_02_finding, end_02_control["entity_label"]))

    # TPR-01 output

    print("\n## TPR-01 Control Exceptions")
    print("----------------------------")

    if tpr_01_exceptions.empty:
        print("No control exceptions identified.")
    else:
        print(tpr_01_exceptions.to_string(index=False))

    # Missing security-review evidence does not establish control failure.
    print("\n## TPR-01 Evidence Issues")
    print("-------------------------")

    if tpr_01_evidence_issues.empty:
        print("No evidence issues identified.")
    else:
        print(tpr_01_evidence_issues.to_string(index=False))

    print("\n## TPR-01 Control Finding")
    print("-------------------------")

    print(format_control_finding(tpr_01_finding, tpr_01_control["entity_label"]))

    # TPR-02 output

    print("\n## TPR-02 Control Exceptions")
    print("----------------------------")

    if tpr_02_exceptions.empty:
        print("No control exceptions identified.")
    else:
        print(tpr_02_exceptions.to_string(index=False))

    # Missing MFA evidence does not establish control failure.
    print("\n## TPR-02 Evidence Issues")
    print("-------------------------")

    if tpr_02_evidence_issues.empty:
        print("No evidence issues identified.")
    else:
        print(tpr_02_evidence_issues.to_string(index=False))

    print("\n## TPR-02 Control Finding")
    print("-------------------------")

    print(format_control_finding(tpr_02_finding, tpr_02_control["entity_label"]))


if __name__ == "__main__":
    main()
