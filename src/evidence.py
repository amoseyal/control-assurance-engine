import pandas as pd


# Define the minimum fields required for user-account evidence.
#
# A set is useful here because we'll later compare these required
# fields against the columns actually present in the CSV.
REQUIRED_USER_COLUMNS = {
    'username',
    'first_name',
    'last_name',
    'email_address',
    'department',
    'employment_status',
    'enabled',
    'mfa_enabled',
    'is_admin',
    'admin_approved'
}

# Define the employment-status values recognized by the
# Northstar user-evidence model.
#
# Blank values are not included here because they represent
# missing evidence rather than an invalid status.
VALID_EMPLOYMENT_STATUSES = {
    'active',
    'terminated',
    'leave'
}

# Define the columns required in endpoint evidence.
#
# These fields provide the evidence needed by the endpoint
# controls that the Control Assurance Engine will support.
REQUIRED_DEVICE_COLUMNS = {
    'device_id',
    'device_name',
    'assigned_user',
    'device_type',
    'operating_system',
    'company_managed',
    'disk_encrypted',
    'endpoint_protection'
}


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

    # Read the CSV file into a pandas DataFrame.
    #
    # pandas will use the CSV header row as the DataFrame's
    # column names and each subsequent row as an account record.
    users = pd.read_csv(filepath)

    # Determine whether any required evidence fields are missing.
    #
    # set(users.columns) converts the actual CSV column names into a set.
    # Subtracting it from REQUIRED_USER_COLUMNS leaves only the fields
    # that we expected but did not receive.
    missing_columns = REQUIRED_USER_COLUMNS - set(users.columns)

    # If the set contains anything, the evidence schema is incomplete.
    if missing_columns:
        # Sort the names so the error message remains predictable,
        # especially if multiple columns are missing.
        missing_list = ', '.join(sorted(missing_columns))

        # Stop processing and explain exactly which evidence fields
        # are missing.
        raise ValueError(
            f'Missing required columns: {missing_list}'
        )

    # Define the columns that should contain only Boolean values.
    #
    # Blank values are allowed because they represent missing evidence
    # that the control-assessment layer will handle separately.
    boolean_columns = [
        'enabled',
        'mfa_enabled',
        'is_admin',
        'admin_approved']

    # Validate each Boolean field independently.
    for column in boolean_columns:

        # Remove missing values before checking the remaining values.
        #
        # .dropna() is important because a blank value is not considered
        # malformed evidence in our model. It represents missing evidence.
        non_null_values = users[column].dropna()

        # Check whether every non-null value is an actual Boolean.
        #
        # isinstance(value, bool) returns True only when the value
        # is a Python Boolean such as True or False.
        valid_values = non_null_values.map(
            lambda value: isinstance(value, bool)
        )

        # If even one value is not Boolean, reject the evidence file.
        #
        # .all() returns True only when every value in the Series is True.
        if not valid_values.all():
            raise ValueError(
                f"Invalid Boolean value in column '{column}'"
            )

    # Validate employment-status values.
    #
    # dropna() intentionally removes blank values from this validation.
    # A blank employment status represents missing evidence and can be
    # handled later by the relevant control assessment.
    non_null_statuses = users['employment_status'].dropna()

    # Identify any values that are not part of Northstar's approved
    # employment-status vocabulary.
    invalid_statuses = ~non_null_statuses.isin(
        VALID_EMPLOYMENT_STATUSES
    )

    # Reject the evidence file if any unsupported status is present.
    #
    # This prevents spelling mistakes or unexpected values such as
    # 'former', 'inactive', or 'fired' from silently changing the
    # scope of an IAM control.
    if invalid_statuses.any():
        raise ValueError(
            "Invalid value in column 'employment_status'"
        )

    # Return the loaded evidence so that other parts of the
    # assessment engine can evaluate security controls against it.
    return users


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

    # Load the device evidence into a pandas DataFrame.
    devices = pd.read_csv(filepath)


    # Determine whether any required device-evidence columns
    # are missing from the CSV.
    missing_columns = REQUIRED_DEVICE_COLUMNS - set(devices.columns)

    # Reject the evidence if the required schema is incomplete.
    #
    # Sorting the missing columns makes the resulting error
    # message predictable and easier to read.
    if missing_columns:
        missing_list = sorted(missing_columns)

        raise ValueError(
            f'Missing required columns: {missing_list}'
        )

    # Define the device fields that must contain Boolean values
    # whenever evidence is present.
    #
    # Blank values are permitted because missing evidence will
    # later be handled separately by the relevant control.
    boolean_columns = [
        'company_managed',
        'disk_encrypted',
        'endpoint_protection'
    ]

    # Validate each Boolean device-evidence field.
    for column in boolean_columns:

        # Remove blank values before validating the remaining data.
        #
        # This distinguishes missing evidence from invalid evidence.
        non_null_values = devices[column].dropna()

        # Check that every non-blank value was interpreted as
        # a Boolean value by pandas.
        valid_values = non_null_values.map(
            lambda value: isinstance(value, bool)
        )

        # Reject unsupported values such as 'yes', 'encrypted',
        # or 'managed' rather than allowing ambiguous evidence
        # into the control-assessment engine.
        if not valid_values.all():
            raise ValueError(
                f"Invalid Boolean value in column '{column}'"
            )

    # Return the validated endpoint evidence.
    return devices


