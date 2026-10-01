# ============================================================
# CONTROL CATALOG TESTS
# ============================================================

from src.control_catalog import CONTROL_CATALOG


def test_control_catalog_contains_iam_01():
    """
    Verify that IAM-01 is defined in the control catalog with
    the metadata required by the assessment engine.
    """
    control = CONTROL_CATALOG['IAM-01']

    # Verify the control's core identifying information.
    assert control['control_id'] == 'IAM-01'
    assert control['domain'] == 'Identity and Access Management'

    # Verify the human-readable control requirement.
    assert (
        control['requirement']
        == 'All active user accounts must have MFA enabled.'
    )

    # Verify the evidence and entity metadata used by reporting.
    assert control['evidence_source'] == 'users.csv'
    assert control['entity_label'] == 'Accounts'


def test_control_catalog_contains_iam_02():
    """
    Verify that IAM-02 is defined in the control catalog with
    the metadata required by the assessment engine.
    """
    control = CONTROL_CATALOG['IAM-02']

    # Verify the control's core identifying information.
    assert control['control_id'] == 'IAM-02'
    assert control['domain'] == 'Identity and Access Management'

    # Verify the human-readable control requirement.
    assert (
        control['requirement']
        == 'Terminated users must have their accounts disabled.'
    )

    # Verify the evidence and entity metadata used by reporting.
    assert control['evidence_source'] == 'users.csv'
    assert control['entity_label'] == 'Accounts'


def test_control_catalog_contains_iam_03():
    """
    Verify that IAM-03 is defined in the control catalog with
    the metadata required by the assessment engine.
    """
    control = CONTROL_CATALOG['IAM-03']

    # Verify the control's core identifying information.
    assert control['control_id'] == 'IAM-03'
    assert control['domain'] == 'Identity and Access Management'

    # Verify the human-readable control requirement.
    assert (
        control['requirement']
        == 'Administrative privileges must be limited to approved accounts.'
    )

    # Verify the evidence and entity metadata used by reporting.
    assert control['evidence_source'] == 'users.csv'
    assert control['entity_label'] == 'Accounts'


def test_control_catalog_contains_end_01():
    """
    Verify that END-01 is defined in the control catalog with
    the metadata required by the assessment engine.
    """
    control = CONTROL_CATALOG['END-01']

    # Verify the control's core identifying information.
    assert control['control_id'] == 'END-01'
    assert control['domain'] == 'Endpoint Security'

    # Verify the human-readable control requirement.
    assert (
        control['requirement']
        == 'Company-managed endpoints must use disk encryption.'
    )

    # Verify the evidence and entity metadata used by reporting.
    assert control['evidence_source'] == 'devices.csv'
    assert control['entity_label'] == 'Devices'


def test_control_catalog_contains_end_02():
    """
    Verify that END-02 is defined in the control catalog with
    the metadata required by the assessment engine.
    """
    control = CONTROL_CATALOG['END-02']

    # Verify the control's core identifying information.
    assert control['control_id'] == 'END-02'
    assert control['domain'] == 'Endpoint Security'

    # Verify the human-readable control requirement.
    assert (
        control['requirement']
        == 'Company-managed endpoints must have endpoint protection enabled.'
    )

    # Verify the evidence and entity metadata used by reporting.
    assert control['evidence_source'] == 'devices.csv'
    assert control['entity_label'] == 'Devices'



# ============================================================
# NIST CSF 2.0 MAPPING VERIFICATION TESTS
# ============================================================

def test_iam_01_maps_to_nist_csf():
    """
    Verify that IAM-01 maps to the appropriate
    NIST Cybersecurity Framework 2.0 outcome.
    """
    control = CONTROL_CATALOG['IAM-01']

    # Verify the NIST CSF 2.0 function.
    assert control['nist_csf_function'] == 'Protect'

    # Verify the NIST CSF 2.0 category.
    assert control['nist_csf_category'] == 'PR.AA'
    assert (
        control['nist_csf_category_name']
        == 'Identity Management, Authentication, and Access Control'
    )

    # Verify the NIST CSF 2.0 subcategory and outcome.
    assert control['nist_csf_subcategory'] == 'PR.AA-03'
    assert (
        control['nist_csf_subcategory_outcome']
        == 'Users, services, and hardware are authenticated'
    )


def test_iam_02_maps_to_nist_csf():
    """
    Verify that IAM-02 maps to the appropriate
    NIST Cybersecurity Framework 2.0 outcome.
    """
    control = CONTROL_CATALOG['IAM-02']

    # Verify the NIST CSF 2.0 function.
    assert control['nist_csf_function'] == 'Protect'

    # Verify the NIST CSF 2.0 category.
    assert control['nist_csf_category'] == 'PR.AA'
    assert (
        control['nist_csf_category_name']
        == 'Identity Management, Authentication, and Access Control'
    )

    # Verify the NIST CSF 2.0 subcategory and outcome.
    assert control['nist_csf_subcategory'] == 'PR.AA-05'
    assert (
        control['nist_csf_subcategory_outcome']
        == (
            'Access permissions, entitlements, and authorizations are '
            'defined in a policy, managed, enforced, and reviewed, and '
            'incorporate the principles of least privilege and '
            'separation of duties'
        )
    )


def test_iam_03_maps_to_nist_csf():
    """
    Verify that IAM-03 maps to the appropriate
    NIST Cybersecurity Framework 2.0 outcome.
    """
    control = CONTROL_CATALOG['IAM-03']

    # Verify the NIST CSF 2.0 function.
    assert control['nist_csf_function'] == 'Protect'

    # Verify the NIST CSF 2.0 category.
    assert control['nist_csf_category'] == 'PR.AA'
    assert (
        control['nist_csf_category_name']
        == 'Identity Management, Authentication, and Access Control'
    )

    # Verify the NIST CSF 2.0 subcategory and outcome.
    assert control['nist_csf_subcategory'] == 'PR.AA-05'
    assert (
        control['nist_csf_subcategory_outcome']
        == (
            'Access permissions, entitlements, and authorizations are '
            'defined in a policy, managed, enforced, and reviewed, and '
            'incorporate the principles of least privilege and '
            'separation of duties'
        )
    )


def test_end_01_maps_to_nist_csf():
    """
    Verify that END-01 maps to the appropriate
    NIST Cybersecurity Framework 2.0 outcome.
    """
    control = CONTROL_CATALOG['END-01']

    # Verify the NIST CSF 2.0 function.
    assert control['nist_csf_function'] == 'Protect'

    # Verify the NIST CSF 2.0 category.
    assert control['nist_csf_category'] == 'PR.DS'
    assert control['nist_csf_category_name'] == 'Data Security'

    # Verify the NIST CSF 2.0 subcategory and outcome.
    assert control['nist_csf_subcategory'] == 'PR.DS-01'
    assert (
        control['nist_csf_subcategory_outcome']
        == (
            'The confidentiality, integrity, and availability '
            'of data-at-rest are protected'
        )
    )


def test_end_02_maps_to_nist_csf():
    """
    Verify that END-02 maps to the appropriate
    NIST Cybersecurity Framework 2.0 outcome.
    """
    control = CONTROL_CATALOG['END-02']

    # Verify the NIST CSF 2.0 function.
    assert control['nist_csf_function'] == 'Protect'

    # Verify the NIST CSF 2.0 category.
    assert control['nist_csf_category'] == 'PR.PS'
    assert control['nist_csf_category_name'] == 'Platform Security'

    # Verify the NIST CSF 2.0 subcategory and outcome.
    assert control['nist_csf_subcategory'] == 'PR.PS-05'
    assert (
        control['nist_csf_subcategory_outcome']
        == (
            'Installation and execution of unauthorized '
            'software are prevented'
        )
    )



# ============================================================
# TEST RISK METADATA SCHEMA IN CONTROLS CATALOG
# ============================================================

def test_iam_01_has_risk_metadata():
    """
    Verify that IAM-01 defines baseline likelihood and impact
    ratings for use by the risk-assessment layer.
    """

    control = CONTROL_CATALOG['IAM-01']

    # Verify that the control defines its baseline likelihood.
    assert control['likelihood'] == 4

    # Verify that the control defines its baseline impact.
    assert control['impact'] == 4


def test_iam_02_has_risk_metadata():
    """
    Verify that IAM-02 defines baseline likelihood and impact
    ratings for use by the risk-assessment layer.
    """

    control = CONTROL_CATALOG['IAM-02']

    # Terminated-account access is considered possible
    # within the Northstar BuildCo assessment scenario.
    assert control['likelihood'] == 3

    # Unauthorized access through a former employee account
    # could have severe business and security consequences.
    assert control['impact'] == 5


def test_iam_03_has_risk_metadata():
    """
    Verify that IAM-03 defines baseline likelihood and impact
    ratings for use by the risk-assessment layer.
    """

    control = CONTROL_CATALOG['IAM-03']

    # Unapproved administrative access is considered possible
    # within the Northstar BuildCo assessment scenario.
    assert control['likelihood'] == 3

    # Misuse or compromise of administrative privileges could
    # have severe consequences across systems and data.
    assert control['impact'] == 5


def test_end_01_has_risk_metadata():
    """
    Verify that END-01 defines baseline likelihood and impact
    ratings for use by the risk-assessment layer.
    """

    control = CONTROL_CATALOG['END-01']

    # Loss or theft of an unencrypted managed endpoint is
    # considered possible in the Northstar BuildCo scenario.
    assert control['likelihood'] == 3

    # Exposure of company data from an unencrypted endpoint
    # could have major business and security consequences.
    assert control['impact'] == 4


def test_end_02_has_risk_metadata():
    """
    Verify that END-02 defines baseline likelihood and impact
    ratings for use by the risk-assessment layer.
    """

    control = CONTROL_CATALOG['END-02']

    # Malware or other malicious software reaching an
    # inadequately protected endpoint is considered likely
    # in the Northstar BuildCo scenario.
    assert control['likelihood'] == 4

    # Compromise of a company-managed endpoint could have
    # major business and security consequences.
    assert control['impact'] == 4



# ============================================================
# THIRD-PARTY RISK CONTROL CATALOG TESTS
# ============================================================

def test_tpr_01_control_catalog_entry():
    """
    Test that TPR-01 is defined in the control catalog with
    the expected control and NIST CSF 2.0 metadata.
    """

    # Retrieve the TPR-01 definition from the centralized
    # control catalog.
    control = CONTROL_CATALOG['TPR-01']

    # Verify the Control Assurance Engine's internal
    # control metadata.
    assert control['control_id'] == 'TPR-01'
    assert control['domain'] == 'Third-Party Risk'
    assert control['requirement'] == (
        'Critical third-party vendors must have a documented '
        'security review.'
    )
    assert control['evidence_source'] == 'vendors.csv'
    assert control['entity_label'] == 'Vendors'

    # Verify the NIST CSF 2.0 mapping.
    assert control['nist_csf_function'] == 'Govern'
    assert control['nist_csf_category'] == 'GV.SC'
    assert control['nist_csf_category_name'] == (
        'Cybersecurity Supply Chain Risk Management'
    )
    assert control['nist_csf_subcategory'] == 'GV.SC-07'
    assert control['nist_csf_subcategory_outcome'] == (
        'The risks posed by a supplier, their products and services, '
        'and other third parties are understood, recorded, prioritized, '
        'assessed, responded to, and monitored over the course of the '
        'relationship'
    )

    # Verify Northstar BuildCo's baseline risk assumptions
    # for a failed TPR-01 control assessment.
    #
    # These ratings are scenario-specific risk assumptions
    # defined by the Control Assurance Engine. They are not
    # prescribed by NIST CSF 2.0.
    assert control['likelihood'] == 3
    assert control['impact'] == 4


def test_tpr_02_control_catalog_entry():
    """
    Test that TPR-02 contains the required control metadata,
    NIST CSF 2.0 mapping, and baseline risk ratings.
    """

    # Retrieve the TPR-02 control definition from the
    # centralized control catalog.
    control = CONTROL_CATALOG['TPR-02']

    # Verify the core control metadata.
    assert control['control_id'] == 'TPR-02'
    assert control['domain'] == 'Third-Party Risk'
    assert control['requirement'] == (
        'Third-party vendors with privileged access must use MFA.'
    )
    assert control['evidence_source'] == 'vendors.csv'
    assert control['entity_label'] == 'Vendors'

    # Verify the NIST CSF 2.0 mapping.
    #
    # TPR-02 is an access-control requirement, so it maps to
    # the Protect function and the Identity Management,
    # Authentication, and Access Control category.
    assert control['nist_csf_function'] == 'Protect'
    assert control['nist_csf_category'] == 'PR.AA'
    assert control['nist_csf_category_name'] == (
        'Identity Management, Authentication, and Access Control'
    )
    assert control['nist_csf_subcategory'] == 'PR.AA-03'
    assert control['nist_csf_subcategory_outcome'] == (
        'Users, services, and hardware are authenticated'
    )

    # Verify Northstar's baseline risk assumptions.
    #
    # Privileged third-party access can provide elevated access
    # to company systems, making an authentication failure
    # potentially significant.
    assert control['likelihood'] == 3
    assert control['impact'] == 5


