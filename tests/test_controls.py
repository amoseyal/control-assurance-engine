"""Tests for IAM, endpoint, and third-party risk controls."""

import pandas as pd

from src.controls import (
    assess_end_01,
    assess_end_02,
    assess_iam_01,
    assess_iam_02,
    assess_iam_03,
    assess_tpr_01,
    assess_tpr_02,
)

# IAM-01 control tests


def test_iam_01_flags_active_users_without_mfa():
    """Verify that IAM-01 flags active accounts without MFA."""
    # Include active accounts with and without MFA, plus a disabled
    # account that is outside IAM-01's scope.
    users = pd.DataFrame(
        [
            {"username": "jcarter", "enabled": True, "mfa_enabled": True},
            {"username": "mlopez", "enabled": True, "mfa_enabled": False},
            {"username": "rsmith", "enabled": False, "mfa_enabled": False},
            {"username": "snguyen", "enabled": True, "mfa_enabled": False},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_01(users)

    assert set(exceptions["username"]) == {"mlopez", "snguyen"}

    assert evidence_issues.empty

    # Only active accounts with known MFA status are assessable.
    assert set(assessable_population["username"]) == {"jcarter", "mlopez", "snguyen"}


def test_iam_01_identifies_missing_account_status():
    """Verify that missing account status is reported separately."""
    # jcarter has complete evidence.
    #
    # tgreen has MFA enabled, but the account's enabled status
    # is unknown. Therefore, we cannot determine whether tgreen
    # belongs in IAM-01's active-account population.
    users = pd.DataFrame(
        [
            {"username": "jcarter", "enabled": True, "mfa_enabled": True},
            {"username": "tgreen", "enabled": None, "mfa_enabled": True},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_01(users)

    assert exceptions.empty

    # Unknown account status is an evidence issue, not a confirmed exception.
    assert set(evidence_issues["username"]) == {"tgreen"}

    # Only jcarter has enough evidence to be assessed.
    assert set(assessable_population["username"]) == {"jcarter"}


def test_iam_01_ignores_missing_mfa_for_disabled_users():
    """Verify that disabled accounts are outside IAM-01's scope."""
    users = pd.DataFrame(
        [{"username": "disabled_user", "enabled": False, "mfa_enabled": None}]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_01(users)

    assert evidence_issues.empty

    assert assessable_population.empty

    assert exceptions.empty


# IAM-02 control tests


def test_iam_02_flags_terminated_users_with_enabled_accounts():
    """Verify that IAM-02 flags enabled accounts belonging to terminated users."""
    # IAM-02 applies to terminated employees and checks that accounts
    # are disabled.
    users = pd.DataFrame(
        [
            {"username": "jcarter", "employment_status": "active", "enabled": True},
            {"username": "mlopez", "employment_status": "active", "enabled": True},
            {"username": "rsmith", "employment_status": "terminated", "enabled": False},
            {"username": "etest", "employment_status": "terminated", "enabled": True},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_02(users)

    assert set(exceptions["username"]) == {"etest"}

    assert evidence_issues.empty

    # Only terminated users with known account status are assessable.
    assert set(assessable_population["username"]) == {"rsmith", "etest"}


def test_iam_02_identifies_missing_account_status():
    """Verify that missing account status is reported separately."""
    # rsmith is compliant; tgreen's account status is unknown.
    users = pd.DataFrame(
        [
            {"username": "rsmith", "employment_status": "terminated", "enabled": False},
            {"username": "tgreen", "employment_status": "terminated", "enabled": None},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_02(users)

    assert exceptions.empty

    # Missing account status is an evidence issue, not a control failure.
    assert set(evidence_issues["username"]) == {"tgreen"}

    # Only rsmith has sufficient evidence for assessment.
    assert set(assessable_population["username"]) == {"rsmith"}


def test_iam_02_ignores_missing_account_status_for_active_users():
    """Verify that active users are outside IAM-02's scope."""
    # Active users are outside IAM-02's scope, even if account status
    # is unknown.
    users = pd.DataFrame(
        [{"username": "tgreen", "employment_status": "active", "enabled": None}]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_02(users)

    assert exceptions.empty

    assert evidence_issues.empty

    assert assessable_population.empty


# IAM-03 control tests


def test_iam_03_flags_unapproved_admin_accounts():
    """Verify that IAM-03 flags unapproved administrative accounts."""
    # Include a standard user, an approved administrator, and an
    # administrator without approval.
    users = pd.DataFrame(
        [
            {"username": "jcarter", "is_admin": False, "admin_approved": False},
            {"username": "dthomas", "is_admin": True, "admin_approved": True},
            {"username": "mlopez", "is_admin": True, "admin_approved": False},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_03(users)

    assert set(exceptions["username"]) == {"mlopez"}

    assert evidence_issues.empty

    # IAM-03 assesses administrative accounts only.
    assert set(assessable_population["username"]) == {"dthomas", "mlopez"}


def test_iam_03_identifies_missing_admin_approval():
    """Verify that missing admin approval is reported as an evidence issue."""
    # kpatel's administrative approval status is unknown.
    users = pd.DataFrame(
        [
            {"username": "dthomas", "is_admin": True, "admin_approved": True},
            {"username": "kpatel", "is_admin": True, "admin_approved": None},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_03(users)

    assert exceptions.empty

    # Missing approval evidence is an evidence issue, not a control failure.
    assert set(evidence_issues["username"]) == {"kpatel"}

    # Only dthomas has sufficient evidence for assessment.
    assert set(assessable_population["username"]) == {"dthomas"}


def test_iam_03_ignores_missing_approval_for_non_admin_accounts():
    """Verify that non-admin accounts are outside IAM-03's scope."""
    # IAM-03 does not apply to a known non-admin account.
    users = pd.DataFrame(
        [{"username": "jcarter", "is_admin": False, "admin_approved": None}]
    )

    exceptions, evidence_issues, assessable_population = assess_iam_03(users)

    assert exceptions.empty

    assert evidence_issues.empty

    assert assessable_population.empty


# END-01 control tests


def test_end_01_flags_unencrypted_company_managed_devices():
    """Verify that END-01 flags unencrypted managed devices."""
    # Include managed encrypted and unencrypted devices, plus an
    # unmanaged device outside END-01's scope.
    devices = pd.DataFrame(
        [
            {"device_id": "DEV-001", "company_managed": True, "disk_encrypted": True},
            {"device_id": "DEV-002", "company_managed": True, "disk_encrypted": False},
            {"device_id": "DEV-003", "company_managed": False, "disk_encrypted": False},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_end_01(devices)

    assert set(exceptions["device_id"]) == {"DEV-002"}

    assert evidence_issues.empty

    # Only managed devices with known encryption status are assessable.
    assert set(assessable_population["device_id"]) == {"DEV-001", "DEV-002"}


def test_end_01_identifies_missing_encryption_status():
    """Verify that missing encryption status is reported as an evidence issue."""
    # DEV-007 is managed, but its encryption status is unknown.
    devices = pd.DataFrame(
        [
            {"device_id": "DEV-001", "company_managed": True, "disk_encrypted": True},
            {"device_id": "DEV-007", "company_managed": True, "disk_encrypted": None},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_end_01(devices)

    assert exceptions.empty

    # Missing encryption status is an evidence issue, not a control failure.
    assert set(evidence_issues["device_id"]) == {"DEV-007"}

    assert set(assessable_population["device_id"]) == {"DEV-001"}


def test_end_01_ignores_missing_encryption_for_unmanaged_devices():
    """Verify that unmanaged devices are outside END-01's scope."""
    # Unmanaged devices are outside END-01's scope despite missing
    # encryption status.
    devices = pd.DataFrame(
        [
            {
                "device_id": "PERSONAL-LT-01",
                "company_managed": False,
                "disk_encrypted": None,
            }
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_end_01(devices)

    assert exceptions.empty

    assert evidence_issues.empty

    assert assessable_population.empty


# END-02 control tests


def test_end_02_flags_unprotected_company_managed_devices():
    """Verify that END-02 flags managed devices without endpoint protection."""
    # Include managed protected and unprotected devices, plus an
    # unmanaged device outside END-02's scope.
    devices = pd.DataFrame(
        [
            {
                "device_id": "DEV-001",
                "company_managed": True,
                "endpoint_protection": True,
            },
            {
                "device_id": "DEV-002",
                "company_managed": True,
                "endpoint_protection": False,
            },
            {
                "device_id": "PERSONAL-LT-01",
                "company_managed": False,
                "endpoint_protection": False,
            },
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_end_02(devices)

    assert set(exceptions["device_id"]) == {"DEV-002"}

    assert evidence_issues.empty

    # Only managed devices with known protection status are assessable.
    assert set(assessable_population["device_id"]) == {"DEV-001", "DEV-002"}


def test_end_02_identifies_missing_endpoint_protection_status():
    """Verify that missing endpoint-protection status is an evidence issue."""
    # DEV-007 is managed, but its endpoint-protection status is unknown.
    devices = pd.DataFrame(
        [
            {
                "device_id": "DEV-001",
                "company_managed": True,
                "endpoint_protection": True,
            },
            {
                "device_id": "DEV-007",
                "company_managed": True,
                "endpoint_protection": None,
            },
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_end_02(devices)

    assert exceptions.empty

    # Missing protection status is an evidence issue, not a control failure.
    assert set(evidence_issues["device_id"]) == {"DEV-007"}

    assert set(assessable_population["device_id"]) == {"DEV-001"}


def test_end_02_ignores_missing_protection_for_unmanaged_devices():
    """Verify that unmanaged devices are outside END-02's scope."""
    # Unmanaged devices are outside END-02's scope despite missing
    # protection status.
    devices = pd.DataFrame(
        [
            {
                "device_id": "PERSONAL-LT-01",
                "company_managed": False,
                "endpoint_protection": None,
            }
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_end_02(devices)

    assert exceptions.empty

    assert evidence_issues.empty

    assert assessable_population.empty


# TPR-01 control tests


def test_tpr_01_flags_critical_vendors_without_security_review():
    """Verify that TPR-01 flags critical vendors without a security review."""
    # Include reviewed and unreviewed critical vendors, plus a
    # noncritical vendor outside TPR-01's scope.
    vendors = pd.DataFrame(
        [
            {
                "vendor_id": "VND-001",
                "critical_vendor": True,
                "security_review_completed": True,
            },
            {
                "vendor_id": "VND-002",
                "critical_vendor": True,
                "security_review_completed": False,
            },
            {
                "vendor_id": "VND-003",
                "critical_vendor": False,
                "security_review_completed": False,
            },
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_01(vendors)

    assert set(exceptions["vendor_id"]) == {"VND-002"}

    assert evidence_issues.empty

    # Only critical vendors with known review status are assessable.
    assert set(assessable_population["vendor_id"]) == {"VND-001", "VND-002"}


def test_tpr_01_identifies_missing_security_review_status():
    """Verify that missing security-review status is an evidence issue."""
    # VND-004 is critical, but its security-review status is unknown.
    vendors = pd.DataFrame(
        [
            {
                "vendor_id": "VND-001",
                "critical_vendor": True,
                "security_review_completed": True,
            },
            {
                "vendor_id": "VND-004",
                "critical_vendor": True,
                "security_review_completed": None,
            },
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_01(vendors)

    assert exceptions.empty

    # Missing review status is an evidence issue, not a control failure.
    assert set(evidence_issues["vendor_id"]) == {"VND-004"}

    assert set(assessable_population["vendor_id"]) == {"VND-001"}


def test_tpr_01_ignores_missing_review_for_noncritical_vendors():
    """Verify that noncritical vendors are outside TPR-01's scope."""
    # Noncritical vendors are outside TPR-01's scope even if review
    # status is missing.
    vendors = pd.DataFrame(
        [
            {
                "vendor_id": "VND-007",
                "critical_vendor": False,
                "security_review_completed": None,
            }
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_01(vendors)

    assert exceptions.empty

    assert evidence_issues.empty

    assert assessable_population.empty


def test_tpr_01_identifies_missing_critical_vendor_status():
    """Verify that missing critical-vendor status is an evidence issue."""
    # VND-008's missing critical-vendor classification prevents
    # determining whether TPR-01 applies.
    vendors = pd.DataFrame(
        [
            {
                "vendor_id": "VND-001",
                "critical_vendor": True,
                "security_review_completed": True,
            },
            {
                "vendor_id": "VND-008",
                "critical_vendor": None,
                "security_review_completed": True,
            },
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_01(vendors)

    assert exceptions.empty

    assert set(evidence_issues["vendor_id"]) == {"VND-008"}

    # Only VND-001 has evidence for both scope and compliance.
    assert set(assessable_population["vendor_id"]) == {"VND-001"}


# TPR-02 control tests


def test_tpr_02_flags_privileged_vendors_without_mfa():
    """Verify that TPR-02 flags privileged vendors without MFA."""
    # Include vendors with and without privileged access and MFA.
    vendors = pd.DataFrame(
        [
            {"vendor_id": "VND-001", "privileged_access": True, "mfa_enabled": True},
            {"vendor_id": "VND-002", "privileged_access": True, "mfa_enabled": False},
            {"vendor_id": "VND-003", "privileged_access": False, "mfa_enabled": False},
        ]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_02(vendors)

    assert list(exceptions["vendor_id"]) == ["VND-002"]

    assert evidence_issues.empty

    # TPR-02 assesses privileged vendors only.
    assert list(assessable_population["vendor_id"]) == ["VND-001", "VND-002"]


def test_tpr_02_identifies_missing_mfa_status():
    """Verify that missing MFA status is an evidence issue for in-scope vendors."""
    # The vendor is in scope, but missing MFA status prevents assessment.
    vendors = pd.DataFrame(
        [{"vendor_id": "VND-001", "privileged_access": True, "mfa_enabled": None}]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_02(vendors)

    assert exceptions.empty

    # Missing MFA status is an evidence issue, not a control failure.
    assert list(evidence_issues["vendor_id"]) == ["VND-001"]

    assert assessable_population.empty


def test_tpr_02_ignores_missing_mfa_for_nonprivileged_vendors():
    """Verify that nonprivileged vendors are outside TPR-02's scope."""
    # A known non-privileged vendor is outside TPR-02's scope even if
    # its MFA status is missing.
    vendors = pd.DataFrame(
        [{"vendor_id": "VND-001", "privileged_access": False, "mfa_enabled": None}]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_02(vendors)

    assert exceptions.empty
    assert evidence_issues.empty
    assert assessable_population.empty


def test_tpr_02_identifies_missing_privileged_access_status():
    """Verify that missing privileged-access status is an evidence issue."""
    # MFA status does not resolve missing evidence about whether the
    # vendor is in scope.
    vendors = pd.DataFrame(
        [{"vendor_id": "VND-001", "privileged_access": None, "mfa_enabled": True}]
    )

    exceptions, evidence_issues, assessable_population = assess_tpr_02(vendors)

    assert exceptions.empty

    assert list(evidence_issues["vendor_id"]) == ["VND-001"]

    # The vendor is not assessable until privileged-access status is known.
    assert assessable_population.empty
