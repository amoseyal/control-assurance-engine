"""Tests for control catalog definitions and metadata."""

from src.control_catalog import CONTROL_CATALOG


def test_control_catalog_contains_iam_01():
    """Verify that IAM-01 has the metadata required by the assessment engine."""
    control = CONTROL_CATALOG["IAM-01"]

    assert control["control_id"] == "IAM-01"
    assert control["domain"] == "Identity and Access Management"

    assert control["requirement"] == "All active user accounts must have MFA enabled."

    assert control["evidence_source"] == "users.csv"
    assert control["entity_label"] == "Accounts"

    assert CONTROL_CATALOG["IAM-01"]["finding_description"] == (
        "Active user accounts were identified without MFA enabled, "
        "increasing the risk of unauthorized access if credentials "
        "are compromised."
    )

    assert CONTROL_CATALOG["IAM-01"]["recommendation"] == (
        "Enable MFA for all active user accounts and verify enrollment."
    )


def test_control_catalog_contains_iam_02():
    """Verify that IAM-02 has the metadata required by the assessment engine."""
    control = CONTROL_CATALOG["IAM-02"]

    assert control["control_id"] == "IAM-02"
    assert control["domain"] == "Identity and Access Management"

    assert (
        control["requirement"] == "Terminated users must have their accounts disabled."
    )

    assert control["evidence_source"] == "users.csv"
    assert control["entity_label"] == "Accounts"

    assert CONTROL_CATALOG["IAM-02"]["finding_description"] == (
        "Terminated user accounts were identified as still enabled, "
        "increasing the risk of unauthorized access after employment ends."
    )

    assert CONTROL_CATALOG["IAM-02"]["recommendation"] == (
        "Disable terminated user accounts promptly and verify account "
        "deactivation as part of the offboarding process."
    )


def test_control_catalog_contains_iam_03():
    """Verify that IAM-03 has the metadata required by the assessment engine."""
    control = CONTROL_CATALOG["IAM-03"]

    assert control["control_id"] == "IAM-03"
    assert control["domain"] == "Identity and Access Management"

    assert (
        control["requirement"]
        == "Administrative privileges must be limited to approved accounts."
    )

    assert control["evidence_source"] == "users.csv"
    assert control["entity_label"] == "Accounts"

    assert CONTROL_CATALOG["IAM-03"]["finding_description"] == (
        "Administrative privileges were identified on accounts without "
        "documented approval, increasing the risk of unauthorized "
        "privileged access."
    )

    assert CONTROL_CATALOG["IAM-03"]["recommendation"] == (
        "Remove unapproved administrative privileges or document appropriate "
        "authorization, and periodically review privileged account access."
    )

    assert CONTROL_CATALOG["IAM-03"]["finding_description"] == (
        "Administrative privileges were identified on accounts without "
        "documented approval, increasing the risk of unauthorized "
        "privileged access."
    )

    assert CONTROL_CATALOG["IAM-03"]["recommendation"] == (
        "Remove unapproved administrative privileges or document appropriate "
        "authorization, and periodically review privileged account access."
    )

    assert CONTROL_CATALOG["END-01"]["finding_description"] == (
        "Company-managed endpoints were identified without disk encryption, "
        "increasing the risk of unauthorized access to data if a device "
        "is lost, stolen, or otherwise physically compromised."
    )

    assert CONTROL_CATALOG["END-01"]["recommendation"] == (
        "Enable full-disk encryption on all company-managed endpoints and "
        "periodically verify encryption status through endpoint management."
    )


def test_control_catalog_contains_end_01():
    """Verify that END-01 has the metadata required by the assessment engine."""
    control = CONTROL_CATALOG["END-01"]

    assert control["control_id"] == "END-01"
    assert control["domain"] == "Endpoint Security"

    assert (
        control["requirement"] == "Company-managed endpoints must use disk encryption."
    )

    assert control["evidence_source"] == "devices.csv"
    assert control["entity_label"] == "Devices"


def test_control_catalog_contains_end_02():
    """Verify that END-02 has the metadata required by the assessment engine."""
    control = CONTROL_CATALOG["END-02"]

    assert control["control_id"] == "END-02"
    assert control["domain"] == "Endpoint Security"

    assert (
        control["requirement"]
        == "Company-managed endpoints must have endpoint protection enabled."
    )

    assert control["evidence_source"] == "devices.csv"
    assert control["entity_label"] == "Devices"

    assert CONTROL_CATALOG["END-02"]["finding_description"] == (
        "Company-managed endpoints were identified without endpoint "
        "protection enabled, increasing exposure to malware and other "
        "endpoint-based threats."
    )

    assert CONTROL_CATALOG["END-02"]["recommendation"] == (
        "Enable and centrally manage endpoint protection on all "
        "company-managed endpoints and periodically verify protection status."
    )


# NIST CSF 2.0 mapping tests


def test_iam_01_maps_to_nist_csf():
    """Verify that IAM-01 maps to its NIST CSF 2.0 outcome."""
    control = CONTROL_CATALOG["IAM-01"]

    assert control["nist_csf_function"] == "Protect"

    assert control["nist_csf_category"] == "PR.AA"
    assert (
        control["nist_csf_category_name"]
        == "Identity Management, Authentication, and Access Control"
    )

    assert control["nist_csf_subcategory"] == "PR.AA-03"
    assert (
        control["nist_csf_subcategory_outcome"]
        == "Users, services, and hardware are authenticated"
    )


def test_iam_02_maps_to_nist_csf():
    """Verify that IAM-02 maps to its NIST CSF 2.0 outcome."""
    control = CONTROL_CATALOG["IAM-02"]

    assert control["nist_csf_function"] == "Protect"

    assert control["nist_csf_category"] == "PR.AA"
    assert (
        control["nist_csf_category_name"]
        == "Identity Management, Authentication, and Access Control"
    )

    assert control["nist_csf_subcategory"] == "PR.AA-05"
    assert control["nist_csf_subcategory_outcome"] == (
        "Access permissions, entitlements, and authorizations are "
        "defined in a policy, managed, enforced, and reviewed, and "
        "incorporate the principles of least privilege and "
        "separation of duties"
    )


def test_iam_03_maps_to_nist_csf():
    """Verify that IAM-03 maps to its NIST CSF 2.0 outcome."""
    control = CONTROL_CATALOG["IAM-03"]

    assert control["nist_csf_function"] == "Protect"

    assert control["nist_csf_category"] == "PR.AA"
    assert (
        control["nist_csf_category_name"]
        == "Identity Management, Authentication, and Access Control"
    )

    assert control["nist_csf_subcategory"] == "PR.AA-05"
    assert control["nist_csf_subcategory_outcome"] == (
        "Access permissions, entitlements, and authorizations are "
        "defined in a policy, managed, enforced, and reviewed, and "
        "incorporate the principles of least privilege and "
        "separation of duties"
    )


def test_end_01_maps_to_nist_csf():
    """Verify that END-01 maps to its NIST CSF 2.0 outcome."""
    control = CONTROL_CATALOG["END-01"]

    assert control["nist_csf_function"] == "Protect"

    assert control["nist_csf_category"] == "PR.DS"
    assert control["nist_csf_category_name"] == "Data Security"

    assert control["nist_csf_subcategory"] == "PR.DS-01"
    assert control["nist_csf_subcategory_outcome"] == (
        "The confidentiality, integrity, and availability of data-at-rest are protected"
    )


def test_end_02_maps_to_nist_csf():
    """Verify that END-02 maps to its NIST CSF 2.0 outcome."""
    control = CONTROL_CATALOG["END-02"]

    assert control["nist_csf_function"] == "Protect"

    assert control["nist_csf_category"] == "PR.PS"
    assert control["nist_csf_category_name"] == "Platform Security"

    assert control["nist_csf_subcategory"] == "PR.PS-05"
    assert control["nist_csf_subcategory_outcome"] == (
        "Installation and execution of unauthorized software are prevented"
    )


# Risk metadata tests


def test_iam_01_has_risk_metadata():
    """Verify that IAM-01 defines baseline likelihood and impact ratings."""
    control = CONTROL_CATALOG["IAM-01"]

    assert control["likelihood"] == 4

    assert control["impact"] == 4


def test_iam_02_has_risk_metadata():
    """Verify that IAM-02 defines baseline likelihood and impact ratings."""
    control = CONTROL_CATALOG["IAM-02"]

    # Terminated-account access is considered possible
    # within the Northstar BuildCo assessment scenario.
    assert control["likelihood"] == 3

    # Unauthorized access through a former employee account
    # could have severe business and security consequences.
    assert control["impact"] == 5


def test_iam_03_has_risk_metadata():
    """Verify that IAM-03 defines baseline likelihood and impact ratings."""
    control = CONTROL_CATALOG["IAM-03"]

    # Unapproved administrative access is considered possible
    # within the Northstar BuildCo assessment scenario.
    assert control["likelihood"] == 3

    # Misuse or compromise of administrative privileges could
    # have severe consequences across systems and data.
    assert control["impact"] == 5


def test_end_01_has_risk_metadata():
    """Verify that END-01 defines baseline likelihood and impact ratings."""
    control = CONTROL_CATALOG["END-01"]

    # Loss or theft of an unencrypted managed endpoint is
    # considered possible in the Northstar BuildCo scenario.
    assert control["likelihood"] == 3

    # Exposure of company data from an unencrypted endpoint
    # could have major business and security consequences.
    assert control["impact"] == 4


def test_end_02_has_risk_metadata():
    """Verify that END-02 defines baseline likelihood and impact ratings."""
    control = CONTROL_CATALOG["END-02"]

    # Malware or other malicious software reaching an
    # inadequately protected endpoint is considered likely
    # in the Northstar BuildCo scenario.
    assert control["likelihood"] == 4

    # Compromise of a company-managed endpoint could have
    # major business and security consequences.
    assert control["impact"] == 4


# Third-party risk control catalog tests


def test_tpr_01_control_catalog_entry():
    """Verify TPR-01's control metadata and NIST CSF 2.0 mapping."""
    control = CONTROL_CATALOG["TPR-01"]

    assert control["control_id"] == "TPR-01"
    assert control["domain"] == "Third-Party Risk"
    assert control["requirement"] == (
        "Critical third-party vendors must have a documented security review."
    )
    assert control["evidence_source"] == "vendors.csv"
    assert control["entity_label"] == "Vendors"

    assert control["nist_csf_function"] == "Govern"
    assert control["nist_csf_category"] == "GV.SC"
    assert control["nist_csf_category_name"] == (
        "Cybersecurity Supply Chain Risk Management"
    )
    assert control["nist_csf_subcategory"] == "GV.SC-07"
    assert control["nist_csf_subcategory_outcome"] == (
        "The risks posed by a supplier, their products and services, "
        "and other third parties are understood, recorded, prioritized, "
        "assessed, responded to, and monitored over the course of the "
        "relationship"
    )

    # These scenario-specific assumptions are defined by the engine,
    # not prescribed by NIST CSF 2.0.
    assert control["likelihood"] == 3
    assert control["impact"] == 4

    assert CONTROL_CATALOG["TPR-01"]["finding_description"] == (
        "Critical third-party vendors were identified without a documented "
        "security review, limiting the organization's ability to understand "
        "and manage cybersecurity risks introduced by those vendors."
    )

    assert CONTROL_CATALOG["TPR-01"]["recommendation"] == (
        "Complete and document security reviews for all critical third-party "
        "vendors and establish a process for periodic reassessment."
    )


def test_tpr_02_control_catalog_entry():
    """Verify TPR-02's control metadata, NIST mapping, and risk ratings."""
    control = CONTROL_CATALOG["TPR-02"]

    assert control["control_id"] == "TPR-02"
    assert control["domain"] == "Third-Party Risk"
    assert control["requirement"] == (
        "Third-party vendors with privileged access must use MFA."
    )
    assert control["evidence_source"] == "vendors.csv"
    assert control["entity_label"] == "Vendors"

    # TPR-02 is an access-control requirement, so it maps to
    # the Protect function and the Identity Management,
    # Authentication, and Access Control category.
    assert control["nist_csf_function"] == "Protect"
    assert control["nist_csf_category"] == "PR.AA"
    assert control["nist_csf_category_name"] == (
        "Identity Management, Authentication, and Access Control"
    )
    assert control["nist_csf_subcategory"] == "PR.AA-03"
    assert control["nist_csf_subcategory_outcome"] == (
        "Users, services, and hardware are authenticated"
    )

    # Privileged third-party access can provide elevated access
    # to company systems, making an authentication failure
    # potentially significant.
    assert control["likelihood"] == 3
    assert control["impact"] == 5

    assert CONTROL_CATALOG["TPR-02"]["finding_description"] == (
        "Third-party vendors with privileged access were identified without "
        "MFA enabled, increasing the risk that compromised vendor credentials "
        "could be used to gain unauthorized privileged access."
    )

    assert CONTROL_CATALOG["TPR-02"]["recommendation"] == (
        "Require MFA for all third-party vendors with privileged access and "
        "periodically verify that MFA remains enforced."
    )
