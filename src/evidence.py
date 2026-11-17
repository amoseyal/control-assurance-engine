"""
Load and validate security control evidence from CSV files.

Define required evidence schemas and validate user-account,
endpoint, and third-party vendor records.
"""

import pandas as pd

# User evidence configuration
# Required fields for evaluating identity and access management controls.
REQUIRED_USER_COLUMNS = {
    "username",
    "first_name",
    "last_name",
    "email_address",
    "department",
    "employment_status",
    "enabled",
    "mfa_enabled",
    "is_admin",
    "admin_approved",
}

# Blank statuses represent missing evidence, not invalid employment values.
VALID_EMPLOYMENT_STATUSES = {"active", "terminated", "leave"}


# Device evidence configuration
# Required fields for evaluating endpoint security controls.
REQUIRED_DEVICE_COLUMNS = {
    "device_id",
    "device_name",
    "assigned_user",
    "device_type",
    "operating_system",
    "company_managed",
    "disk_encrypted",
    "endpoint_protection",
}


# User evidence loader


def load_user_evidence(filepath):
    """
    Load user-account evidence from a CSV file.

    Args:
        filepath:
            Path to the CSV file containing user-account evidence.

    Returns:
        pd.DataFrame:
            User-account evidence loaded into a pandas DataFrame.
    """

    users = pd.read_csv(filepath)

    # Identify required fields missing from the supplied CSV schema.
    missing_columns = REQUIRED_USER_COLUMNS - set(users.columns)

    if missing_columns:
        # Sort column names for deterministic error messages.
        missing_list = ", ".join(sorted(missing_columns))
        raise ValueError(f"Missing required columns: {missing_list}")

    # Blank Boolean fields represent missing evidence, not malformed values.
    boolean_columns = ["enabled", "mfa_enabled", "is_admin", "admin_approved"]

    for column in boolean_columns:
        # Exclude missing evidence from Boolean type validation.
        non_null_values = users[column].dropna()

        valid_values = non_null_values.map(lambda value: isinstance(value, bool))

        if not valid_values.all():
            raise ValueError(f"Invalid Boolean value in column '{column}'")

    # Exclude missing employment statuses from value validation.
    # Missing statuses are handled by the control-assessment layer.
    non_null_statuses = users["employment_status"].dropna()

    invalid_statuses = ~non_null_statuses.isin(VALID_EMPLOYMENT_STATUSES)

    # Reject unsupported statuses to prevent incorrect IAM assessment scope.
    if invalid_statuses.any():
        raise ValueError("Invalid value in column 'employment_status'")

    return users


# Device evidence loader


def load_device_evidence(filepath):
    """
    Load and validate device evidence from a CSV file.

    Args:
        filepath:
            Path to the device-evidence CSV file.

    Returns:
        pandas.DataFrame:
            Validated device evidence.
    """

    devices = pd.read_csv(filepath)

    missing_columns = REQUIRED_DEVICE_COLUMNS - set(devices.columns)

    # Sort missing column names for deterministic error messages.
    if missing_columns:
        missing_list = sorted(missing_columns)

        raise ValueError(f"Missing required columns: {missing_list}")

    # Missing Boolean values are handled by the control-assessment layer.
    boolean_columns = ["company_managed", "disk_encrypted", "endpoint_protection"]

    for column in boolean_columns:
        # Exclude missing evidence from Boolean type validation.
        non_null_values = devices[column].dropna()

        valid_values = non_null_values.map(lambda value: isinstance(value, bool))

        # Reject ambiguous values to preserve evidence integrity.
        if not valid_values.all():
            raise ValueError(f"Invalid Boolean value in column '{column}'")

    return devices


# Vendor evidence configuration
# Required fields for evaluating third-party risk controls.
REQUIRED_VENDOR_COLUMNS = {
    "vendor_id",
    "vendor_name",
    "service_type",
    "critical_vendor",
    "security_review_completed",
    "review_date",
    "privileged_access",
    "mfa_enabled",
}


# Vendor evidence loader


def load_vendor_evidence(filepath):
    """
    Load and validate third-party vendor evidence from a CSV file.

    Args:
        filepath:
            Path to the vendor-evidence CSV file.

    Returns:
        pd.DataFrame:
            Validated third-party vendor evidence.
    """

    vendors = pd.read_csv(filepath)

    missing_columns = REQUIRED_VENDOR_COLUMNS - set(vendors.columns)

    # Reject incomplete schemas before evaluating vendor controls.
    if missing_columns:
        raise ValueError(f"Missing required vendor columns: {sorted(missing_columns)}")

    # Missing Boolean values are handled by the control-assessment layer.
    boolean_columns = [
        "critical_vendor",
        "security_review_completed",
        "privileged_access",
        "mfa_enabled",
    ]

    for column in boolean_columns:
        # Exclude missing evidence from Boolean type validation.
        non_null_values = vendors[column].dropna()

        valid_values = non_null_values.map(lambda value: isinstance(value, bool))

        # Reject ambiguous values to preserve evidence integrity.
        if not valid_values.all():
            raise ValueError(f"Invalid Boolean value in column '{column}'")

    return vendors
