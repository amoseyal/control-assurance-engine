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