import pandas as pd

# Import the control-assessment functions used by these tests.
from src.controls import (
    assess_iam_01,
    assess_iam_02,
    assess_iam_03,
    assess_end_01,
    assess_end_02
)


# ------------------------------------------------------------------
# IAM 01 CONTROL TESTING
# ------------------------------------------------------------------

def test_iam_01_flags_active_users_without_mfa():
    """
    Test that IAM-01 identifies active users without MFA
    as confirmed control exceptions.
    """

    # Create a small sample of user-account evidence.
    #
    # The sample deliberately includes:
    # - an active user with MFA
    # - two active users without MFA
    # - a disabled user without MFA
    #
    # The disabled user should not be considered an IAM-01 exception
    # because IAM-01 applies only to active accounts.
    users = pd.DataFrame([
        {
            'username': 'jcarter',
            'enabled': True,
            'mfa_enabled': True
        },
        {
            'username': 'mlopez',
            'enabled': True,
            'mfa_enabled': False
        },
        {
            'username': 'rsmith',
            'enabled': False,
            'mfa_enabled': False
        },
        {
            'username': 'snguyen',
            'enabled': True,
            'mfa_enabled': False
        }
    ])

    # Run the IAM-01 assessment.
    exceptions, evidence_issues, assessable_population = assess_iam_01(users)

    # Active accounts without MFA should be identified
    # as confirmed control exceptions.
    assert set(exceptions['username']) == {
        'mlopez',
        'snguyen'
    }

    # Every record contains the evidence required for IAM-01,
    # so there should be no evidence-quality issues.
    assert evidence_issues.empty

    # Only active accounts with known MFA status belong in the
    # assessable IAM-01 population.
    assert set(assessable_population['username']) == {
        'jcarter',
        'mlopez',
        'snguyen'
    }


def test_iam_01_identifies_missing_account_status():
    """
    Test that IAM-01 identifies missing account-status evidence
    separately from confirmed control exceptions.
    """

    # jcarter has complete evidence.
    #
    # tgreen has MFA enabled, but the account's enabled status
    # is unknown. Therefore, we cannot determine whether tgreen
    # belongs in IAM-01's active-account population.
    users = pd.DataFrame([
        {
            'username': 'jcarter',
            'enabled': True,
            'mfa_enabled': True
        },
        {
            'username': 'tgreen',
            'enabled': None,
            'mfa_enabled': True
        }
    ])

    # Run the IAM-01 assessment.
    exceptions, evidence_issues, assessable_population = assess_iam_01(users)

    # Neither record is a confirmed control exception.
    assert exceptions.empty

    # tgreen should be reported as an evidence-quality issue
    # because the account's enabled status is unknown.
    assert set(evidence_issues['username']) == {'tgreen'}

    # Only jcarter has enough evidence to be included in the
    # assessable IAM-01 population.
    assert set(assessable_population['username']) == {'jcarter'}


def test_iam_01_ignores_missing_mfa_for_disabled_users():
    """
    Verify that a disabled account with missing MFA evidence
    is outside the scope of IAM-01 and is not reported as an
    evidence-quality issue.
    """
    users = pd.DataFrame([
        {
            'username': 'disabled_user',
            'enabled': False,
            'mfa_enabled': None
        }
    ])

    # Assess the test evidence against IAM-01.
    exceptions, evidence_issues, assessable_population = (
        assess_iam_01(users)
    )

    # A disabled account is outside the scope of IAM-01.
    # Therefore, missing MFA evidence should not be treated
    # as an evidence-quality issue.
    assert evidence_issues.empty

    # The disabled account should not be part of the
    # assessable IAM-01 population either.
    assert assessable_population.empty

    # It also cannot be a confirmed control exception.
    assert exceptions.empty

# ------------------------------------------------------------------
# IAM 02 CONTROL TESTING
# ------------------------------------------------------------------

def test_iam_02_flags_terminated_users_with_enabled_accounts():
    """
    Test that IAM-02 identifies terminated users whose
    accounts remain enabled.
    """

    # Create a small sample containing active and terminated employees.
    #
    # IAM-02 applies specifically to terminated employees and tests
    # whether their user accounts have been disabled.
    users = pd.DataFrame([
        {
            'username': 'jcarter',
            'employment_status': 'active',
            'enabled': True
        },
        {
            'username': 'mlopez',
            'employment_status': 'active',
            'enabled': True
        },
        {
            'username': 'rsmith',
            'employment_status': 'terminated',
            'enabled': False
        },
        {
            'username': 'etest',
            'employment_status': 'terminated',
            'enabled': True
        }
    ])

    # Run the IAM-02 assessment.
    #
    # As with IAM-01, the control returns:
    # 1. confirmed control exceptions
    # 2. evidence-quality issues
    # 3. the assessable control population
    exceptions, evidence_issues, assessable_population = assess_iam_02(users)

    # etest is terminated but still has an enabled account,
    # making it a confirmed IAM-02 control exception.
    assert set(exceptions['username']) == {'etest'}

    # Every terminated account in this sample contains sufficient
    # evidence, so there should be no evidence-quality issues.
    assert evidence_issues.empty

    # IAM-02's assessable population consists only of terminated
    # users whose account status is known.
    assert set(assessable_population['username']) == {
        'rsmith',
        'etest'
    }


def test_iam_02_identifies_missing_account_status():
    """
    Test that IAM-02 identifies missing account-status evidence
    separately from a confirmed control exception.
    """

    # Create two terminated-user records.
    #
    # rsmith has sufficient evidence and a properly disabled account.
    # tgreen is terminated, but the account status is unknown.
    users = pd.DataFrame([
        {
            'username': 'rsmith',
            'employment_status': 'terminated',
            'enabled': False
        },
        {
            'username': 'tgreen',
            'employment_status': 'terminated',
            'enabled': None
        }
    ])

    # Run the IAM-02 assessment.
    exceptions, evidence_issues, assessable_population = assess_iam_02(users)

    # Neither record is a confirmed exception.
    #
    # rsmith is compliant, while tgreen lacks enough evidence
    # to determine whether the account was properly disabled.
    assert exceptions.empty

    # tgreen should be classified as an evidence-quality issue,
    # not as a control failure.
    assert set(evidence_issues['username']) == {'tgreen'}

    # Only rsmith has sufficient evidence to be included in the
    # assessable IAM-02 population.
    assert set(assessable_population['username']) == {'rsmith'}


def test_iam_02_ignores_missing_account_status_for_active_users():
    """
    Test that IAM-02 does not report missing account-status evidence
    for users who are known to be outside the control's scope.
    """

    # This user is active, so IAM-02 does not apply.
    #
    # Even though the enabled value is missing, we already have
    # sufficient evidence to determine that this user is outside
    # the terminated-user population tested by IAM-02.
    users = pd.DataFrame([
        {
            'username': 'tgreen',
            'employment_status': 'active',
            'enabled': None
        }
    ])

    # Run the IAM-02 assessment.
    exceptions, evidence_issues, assessable_population = assess_iam_02(users)

    # An active employee cannot be an IAM-02 exception.
    assert exceptions.empty

    # Missing enabled status should not be an IAM-02 evidence issue
    # because the user is already known to be outside this control's scope.
    assert evidence_issues.empty

    # Active employees are not part of the IAM-02 population.
    assert assessable_population.empty


# ------------------------------------------------------------------
# IAM 03 CONTROL TESTING
# ------------------------------------------------------------------

def test_iam_03_flags_unapproved_admin_accounts():
    """
    Test that IAM-03 identifies administrative accounts
    that do not have documented approval.
    """

    # Create a small sample containing both standard and
    # administrative user accounts.
    #
    # jcarter is a standard user and is outside IAM-03's scope.
    # dthomas has approved administrative access.
    # mlopez has administrative access without approval.
    users = pd.DataFrame([
        {
            'username': 'jcarter',
            'is_admin': False,
            'admin_approved': False
        },
        {
            'username': 'dthomas',
            'is_admin': True,
            'admin_approved': True
        },
        {
            'username': 'mlopez',
            'is_admin': True,
            'admin_approved': False
        }
    ])

    # Run the IAM-03 assessment.
    #
    # As with our other controls, IAM-03 will return:
    # 1. confirmed control exceptions
    # 2. evidence-quality issues
    # 3. the assessable control population
    exceptions, evidence_issues, assessable_population = assess_iam_03(users)

    # mlopez has administrative privileges without documented
    # approval and therefore represents a confirmed exception.
    assert set(exceptions['username']) == {'mlopez'}

    # All administrative accounts have sufficient evidence
    # to determine whether their privileges were approved.
    assert evidence_issues.empty

    # Only accounts with administrative privileges belong in
    # IAM-03's assessable population.
    assert set(assessable_population['username']) == {
        'dthomas',
        'mlopez'
    }


def test_iam_03_identifies_missing_admin_approval():
    """
    Test that IAM-03 identifies missing approval evidence for
    accounts known to have administrative privileges.
    """

    # Create two administrative accounts.
    #
    # dthomas has documented approval for administrative access.
    # kpatel is an administrator, but the approval status is missing.
    users = pd.DataFrame([
        {
            'username': 'dthomas',
            'is_admin': True,
            'admin_approved': True
        },
        {
            'username': 'kpatel',
            'is_admin': True,
            'admin_approved': None
        }
    ])

    # Run the IAM-03 assessment.
    exceptions, evidence_issues, assessable_population = assess_iam_03(users)

    # Neither account is a confirmed control exception.
    #
    # dthomas is compliant, while kpatel cannot be evaluated because
    # the required approval evidence is missing.
    assert exceptions.empty

    # kpatel should be classified as an evidence-quality issue,
    # not as a confirmed control failure.
    assert set(evidence_issues['username']) == {'kpatel'}

    # Only dthomas has sufficient evidence to be included in the
    # assessable IAM-03 population.
    assert set(assessable_population['username']) == {'dthomas'}


def test_iam_03_ignores_missing_approval_for_non_admin_accounts():
    """
    Test that IAM-03 does not report missing approval evidence
    for accounts known not to have administrative privileges.
    """

    # This account is known to be a standard, non-admin account.
    #
    # Because is_admin is False, IAM-03 does not apply.
    # Therefore, a missing admin_approved value should not be
    # treated as an IAM-03 evidence-quality issue.
    users = pd.DataFrame([
        {
            'username': 'jcarter',
            'is_admin': False,
            'admin_approved': None
        }
    ])

    # Run the IAM-03 assessment.
    exceptions, evidence_issues, assessable_population = assess_iam_03(users)

    # A non-admin account cannot violate IAM-03.
    assert exceptions.empty

    # Missing approval evidence does not matter for a user who
    # is already known to be outside IAM-03's scope.
    assert evidence_issues.empty

    # Non-admin accounts are not part of the IAM-03
    # assessable population.
    assert assessable_population.empty


# ------------------------------------------------------------------
# END 01 CONTROL TESTING
# ------------------------------------------------------------------

def test_end_01_flags_unencrypted_company_managed_devices():
    """
    Test that END-01 identifies company-managed devices
    that do not use disk encryption.
    """

    # Create a small sample containing both company-managed
    # and personally owned devices.
    #
    # DEV-001 is managed and encrypted.
    # DEV-002 is managed but not encrypted.
    # DEV-003 is not company-managed and is therefore outside
    # the scope of END-01.
    devices = pd.DataFrame([
        {
            'device_id': 'DEV-001',
            'company_managed': True,
            'disk_encrypted': True
        },
        {
            'device_id': 'DEV-002',
            'company_managed': True,
            'disk_encrypted': False
        },
        {
            'device_id': 'DEV-003',
            'company_managed': False,
            'disk_encrypted': False
        }
    ])

    # Run the END-01 assessment.
    #
    # END-01 follows the same assessment pattern as our IAM controls:
    # 1. confirmed control exceptions
    # 2. evidence-quality issues
    # 3. assessable control population
    exceptions, evidence_issues, assessable_population = assess_end_01(
        devices
    )

    # DEV-002 is company-managed but unencrypted, making it
    # a confirmed END-01 control exception.
    assert set(exceptions['device_id']) == {'DEV-002'}

    # All records contain sufficient evidence to determine
    # their END-01 scope and compliance status.
    assert evidence_issues.empty

    # Only company-managed devices with known encryption status
    # belong in the assessable END-01 population.
    assert set(assessable_population['device_id']) == {
        'DEV-001',
        'DEV-002'
    }


def test_end_01_identifies_missing_encryption_status():
    """
    Test that END-01 identifies missing disk-encryption evidence
    for company-managed devices.
    """

    # Create two company-managed endpoint records.
    #
    # DEV-001 has sufficient evidence and is encrypted.
    # DEV-007 is company-managed, but its encryption status
    # is unknown.
    devices = pd.DataFrame([
        {
            'device_id': 'DEV-001',
            'company_managed': True,
            'disk_encrypted': True
        },
        {
            'device_id': 'DEV-007',
            'company_managed': True,
            'disk_encrypted': None
        }
    ])

    # Run the END-01 assessment.
    exceptions, evidence_issues, assessable_population = assess_end_01(
        devices
    )

    # Neither device is a confirmed control exception.
    #
    # DEV-001 is compliant, while DEV-007 cannot be evaluated
    # because its disk-encryption evidence is missing.
    assert exceptions.empty

    # DEV-007 should be classified as an evidence-quality issue,
    # not as a confirmed control failure.
    assert set(evidence_issues['device_id']) == {'DEV-007'}

    # Only DEV-001 has sufficient evidence to be included in
    # the assessable END-01 population.
    assert set(assessable_population['device_id']) == {'DEV-001'}


def test_end_01_ignores_missing_encryption_for_unmanaged_devices():
    """
    Test that END-01 does not report missing encryption evidence
    for devices known to be outside the control's scope.
    """

    # This device is not company-managed, so END-01 does not apply.
    #
    # Even though disk_encrypted is missing, we already have
    # sufficient evidence to determine that the device is outside
    # the company-managed endpoint population.
    devices = pd.DataFrame([
        {
            'device_id': 'PERSONAL-LT-01',
            'company_managed': False,
            'disk_encrypted': None
        }
    ])

    # Run the END-01 assessment.
    exceptions, evidence_issues, assessable_population = assess_end_01(
        devices
    )

    # An unmanaged device cannot be an END-01 control exception.
    assert exceptions.empty

    # Missing encryption evidence does not matter for a device
    # already known to be outside END-01's scope.
    assert evidence_issues.empty

    # Unmanaged devices are not part of the END-01
    # assessable population.
    assert assessable_population.empty


# ------------------------------------------------------------------
# END 02 CONTROL TESTING
# ------------------------------------------------------------------

def test_end_02_flags_unprotected_company_managed_devices():
    """
    Test that END-02 identifies company-managed devices
    that do not have endpoint protection enabled.
    """

    # Create a small endpoint population containing both
    # company-managed and personally owned devices.
    #
    # DEV-001 is managed and protected.
    # DEV-002 is managed but not protected.
    # PERSONAL-LT-01 is unmanaged and therefore outside
    # the scope of END-02.
    devices = pd.DataFrame([
        {
            'device_id': 'DEV-001',
            'company_managed': True,
            'endpoint_protection': True
        },
        {
            'device_id': 'DEV-002',
            'company_managed': True,
            'endpoint_protection': False
        },
        {
            'device_id': 'PERSONAL-LT-01',
            'company_managed': False,
            'endpoint_protection': False
        }
    ])

    # Run the END-02 assessment.
    exceptions, evidence_issues, assessable_population = assess_end_02(
        devices
    )

    # DEV-002 is a confirmed exception because it is
    # company-managed but lacks endpoint protection.
    assert set(exceptions['device_id']) == {'DEV-002'}

    # Every record contains enough evidence to determine
    # whether END-02 applies and whether the device complies.
    assert evidence_issues.empty

    # Only company-managed devices with known protection status
    # belong in the assessable population.
    assert set(assessable_population['device_id']) == {
        'DEV-001',
        'DEV-002'
    }


def test_end_02_identifies_missing_endpoint_protection_status():
    """
    Test that END-02 identifies missing endpoint-protection evidence
    for company-managed devices.
    """

    # Create two company-managed endpoint records.
    #
    # DEV-001 has endpoint protection enabled and is compliant.
    # DEV-007 is company-managed, but its endpoint-protection
    # status is unknown.
    devices = pd.DataFrame([
        {
            'device_id': 'DEV-001',
            'company_managed': True,
            'endpoint_protection': True
        },
        {
            'device_id': 'DEV-007',
            'company_managed': True,
            'endpoint_protection': None
        }
    ])

    # Run the END-02 assessment.
    exceptions, evidence_issues, assessable_population = assess_end_02(
        devices
    )

    # Neither device is a confirmed control exception.
    #
    # DEV-001 is compliant, while DEV-007 cannot be evaluated
    # because its endpoint-protection evidence is missing.
    assert exceptions.empty

    # DEV-007 should be classified as an evidence-quality issue,
    # not as a confirmed END-02 failure.
    assert set(evidence_issues['device_id']) == {'DEV-007'}

    # Only DEV-001 has sufficient evidence to be included
    # in the assessable END-02 population.
    assert set(assessable_population['device_id']) == {'DEV-001'}


def test_end_02_ignores_missing_protection_for_unmanaged_devices():
    """
    Test that END-02 does not report missing endpoint-protection
    evidence for devices known to be outside the control's scope.
    """

    # This device is not company-managed, so END-02 does not apply.
    #
    # Even though endpoint_protection is missing, we already know
    # enough to determine that the device is outside the control's
    # assessment population.
    devices = pd.DataFrame([
        {
            'device_id': 'PERSONAL-LT-01',
            'company_managed': False,
            'endpoint_protection': None
        }
    ])

    # Run the END-02 assessment.
    exceptions, evidence_issues, assessable_population = assess_end_02(
        devices
    )

    # An unmanaged device cannot be an END-02 control exception.
    assert exceptions.empty

    # Missing endpoint-protection evidence does not matter when
    # the device is already known to be outside END-02's scope.
    assert evidence_issues.empty

    # Unmanaged devices are excluded from the assessable population.
    assert assessable_population.empty


