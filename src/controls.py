import pandas as pd


# ============================================================
# IDENTITY AND ACCESS MANAGEMENT (IAM) CONTROLS
# ============================================================

def assess_iam_01(users):
    """
    Assess IAM-01: all active user accounts must have MFA enabled.
    
    Arguments:
        users (pd.DataFrame):
            user-account evidence containing, at minimum,
            "usernaem, 'enabled', and 'mfa_enabled'.
            
    Returns:
        tuple:
            two pandas DataFrames:

            exceptions:
                active accounts that do not have MFA enabled.

                evidence_issues:
                    accounts that cannot be reliably assessed because
                    required control evidence is missing.
    """

    # Identify records where evidence is insufficient to assess IAM-01.
    #
    # If 'enabled' is missing, we cannot determine whether the account
    # is in scope for the control.
    #
    # If the account is enabled, MFA status is required to assess it.
    # A disabled account is outside the scope of IAM-01, so a missing
    # MFA value for that account is not an evidence-quality issue.
    evidence_issue_mask = (
        users['enabled'].isna()
        | (
            (users['enabled'] == True)
            & users['mfa_enabled'].isna()
        )
    )

    # Keep the records that contain incomplete evidenc.
    evidence_issues = users[evidence_issue_mask]

    # Identify the population that is actually in scope for IAM-01.
    #
    # IAM-01 applies specifically to active user accounts. Therefore,
    # an account belongs in the assessable population only when:
    # - its account status is known
    # - the account is enabled
    # - its MFA status is known
    #
    # Disabled accounts are not control failures; they are simply
    # outside the scope of this particular control requirement.
    assessable_mask = (
        users['enabled'].notna()
        & (users['enabled'] == True)
        & users['mfa_enabled'].notna()
    )

    # Keep only active accounts with sufficient evidence to evaluate MFA.
    assessable_population = users[assessable_mask]

    # Keep only records for which the control can make a determination.
    assessable_population = users[assessable_mask]

    # Identify confirmed IAM-01 control expectations.
    #
    # An account fails IAM-01 only when we KNOW that:
    # 1. the account is enabled, AND
    # 2. MFA is not enabled.
    exception_mask = (
        (users['enabled'] == True)
        & (users['mfa_enabled'] == False)
    )

    # Keep only the records that definitively violate IAM-01.
    exceptions = users[exception_mask]

    # Return the three distinct outputs produced by the assessment:
    # confirmed exceptions, evidence issues, and assessable records.
    return exceptions, evidence_issues, assessable_population


def assess_iam_02(users):
    """
    Assess IAM-02: terminated users must have their accounts disabled.

        Args:
        users:
            DataFrame containing user-account evidence.

    Returns:
        tuple:
            Confirmed control exceptions, evidence-quality issues,
            and the assessable IAM-02 population.
    """

    # Identify records with missing evidence required for IAM-02.
    #
    # There are two situations that prevent us from evaluating IAM-02:
    #
    # 1. employment_status is missing, so we cannot determine whether
    #    the user belongs in the terminated-user population.
    #
    # 2. the user is known to be terminated, but enabled is missing,
    #    so we cannot determine whether the account was disabled.
    #
    # A known active user with a missing enabled value is outside the
    # scope of IAM-02 and therefore is not an IAM-02 evidence issue.
    evidence_issue_mask = (
        users['employment_status'].isna()
        | (
            (users['employment_status'] == 'terminated')
            & users['enabled'].isna()
        )
    )

    # Keep records that cannot be fully evaluated because required
    # IAM-02 evidence is missing.
    evidence_issues = users[evidence_issue_mask]

    # Identify terminated users whose account status is known.
    #
    # Active employees are outside the scope of IAM-02 because this
    # control specifically addresses terminated users.
    assessable_mask = (
        (users['employment_status'] == 'terminated')
        & users['enabled'].notna()
    )

    # Keep only terminated users with sufficient account-status
    # evidence to evaluate the control.
    assessable_population = users[assessable_mask]

    # A confirmed IAM-02 exception exists when:
    # - the employee is terminated
    # - the account remains enabled
    exception_mask = (
        (users['employment_status'] == 'terminated')
        & (users['enabled'] == True)
    )

    # Keep the records that violate IAM-02.
    exceptions = users[exception_mask]

    # Return the three distinct assessment outputs.
    return exceptions, evidence_issues, assessable_population


def assess_iam_03(users):
    """
    Assess IAM-03: Administrative privileges must be limited
    to approved accounts.

    Args:
        users:
            DataFrame containing user-account evidence.

    Returns:
        tuple:
            Confirmed control exceptions, evidence-quality issues,
            and the assessable IAM-03 population.
    """

    # Identify records where we cannot determine whether the account
    # belongs in IAM-03's administrative-account population.
    #
    # If is_admin is missing, we do not know whether the account
    # has administrative privileges and therefore cannot determine
    # whether IAM-03 applies.
    evidence_issue_mask = (
        users['is_admin'].isna()
        | (
            (users['is_admin'] == True)
            & users['admin_approved'].isna()
        )
    )

    # Keep records that cannot be fully evaluated because required
    # IAM-03 evidence is missing.
    evidence_issues = users[evidence_issue_mask]

    # Identify administrative accounts whose approval status is known.
    #
    # Standard user accounts are outside the scope of IAM-03.
    assessable_mask = (
        (users['is_admin'] == True)
        & users['admin_approved'].notna()
    )

    # Keep only administrative accounts with sufficient evidence
    # to evaluate the control.
    assessable_population = users[assessable_mask]

    # A confirmed IAM-03 exception exists when:
    # - the account has administrative privileges
    # - those privileges are not approved
    exception_mask = (
        (users['is_admin'] == True)
        & (users['admin_approved'] == False)
    )

    # Keep the records that violate IAM-03.
    exceptions = users[exception_mask]

    # Return the three distinct assessment outputs.
    return exceptions, evidence_issues, assessable_population


# ============================================================
# ENDPOINT SECURITY (END) CONTROLS
# ============================================================

def assess_end_01(devices):
    """
    Assess END-01: Company-managed endpoints must use disk encryption.

    Args:
        devices:
            DataFrame containing endpoint evidence.

    Returns:
        tuple:
            Confirmed control exceptions, evidence-quality issues,
            and the assessable END-01 population.
    """

    # Identify records where we cannot determine whether the device
    # belongs in END-01's company-managed endpoint population.
    #
    # If company_managed is missing, we cannot determine whether
    # END-01 applies to the device.
    #
    # If the device is known to be company-managed but
    # disk_encrypted is missing, we know the device is in scope
    # but lack sufficient evidence to determine compliance.
    evidence_issue_mask = (
        devices['company_managed'].isna()
        | (
            (devices['company_managed'] == True)
            & devices['disk_encrypted'].isna()
        )
    )

    # Keep devices that cannot be fully evaluated because
    # required END-01 evidence is missing.
    evidence_issues = devices[evidence_issue_mask]

    # Identify company-managed devices whose encryption status
    # is known.
    #
    # Personally owned or otherwise unmanaged devices are outside
    # the scope of END-01.
    assessable_mask = (
        (devices['company_managed'] == True)
        & devices['disk_encrypted'].notna()
    )

    # Keep only devices with sufficient evidence to evaluate
    # END-01 compliance.
    assessable_population = devices[assessable_mask]

    # A confirmed END-01 exception exists when:
    # - the device is company-managed
    # - disk encryption is not enabled
    exception_mask = (
        (devices['company_managed'] == True)
        & (devices['disk_encrypted'] == False)
    )

    # Keep the devices that violate END-01.
    exceptions = devices[exception_mask]

    # Return the three distinct assessment outputs.
    return exceptions, evidence_issues, assessable_population


def assess_end_02(devices):
    """
    Assess END-02: Company-managed endpoints must have
    endpoint protection enabled.

    Args:
        devices:
            DataFrame containing endpoint evidence.

    Returns:
        tuple:
            Confirmed control exceptions, evidence-quality issues,
            and the assessable END-02 population.
    """

    # Identify records where there is not enough evidence
    # to evaluate END-02.
    #
    # If company_managed is missing, we cannot determine
    # whether the device is within the control's scope.
    #
    # If the device is company-managed but endpoint_protection
    # is missing, we know it is in scope but cannot determine
    # whether it complies with END-02.
    evidence_issue_mask = (
        devices['company_managed'].isna()
        | (
            (devices['company_managed'] == True)
            & devices['endpoint_protection'].isna()
        )
    )

    # Keep records with insufficient END-02 evidence separate
    # from confirmed control failures.
    evidence_issues = devices[evidence_issue_mask]

    # The assessable population consists only of company-managed
    # devices whose endpoint-protection status is known.
    assessable_mask = (
        (devices['company_managed'] == True)
        & devices['endpoint_protection'].notna()
    )

    assessable_population = devices[assessable_mask]

    # A confirmed END-02 exception exists when the device is
    # company-managed but endpoint protection is not enabled.
    exception_mask = (
        (devices['company_managed'] == True)
        & (devices['endpoint_protection'] == False)
    )

    exceptions = devices[exception_mask]

    # Return the same three-part assessment structure used
    # throughout the control engine.
    return exceptions, evidence_issues, assessable_population


