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
