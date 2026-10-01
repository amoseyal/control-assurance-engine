import pandas as pd
import pytest

# Import the evidence-loading function used to load and validate
# Northstar's user-account evidence.
from src.evidence import (
    load_user_evidence,
    load_device_evidence,
    load_vendor_evidence
)



# ============================================================
# USER EVIDENCE TESTS
# ============================================================

def test_load_user_evidence(tmp_path):
    """
    Test that user evidence can be loaded from a CSV file.
    """

    # tmp_path is a temporary directory automatically provided by pytest.
    # It lets us create a test CSV without modifying our real data/users.csv.
    test_file = tmp_path / 'users.csv'

    # Create a small CSV containing representative user evidence.
    #
    # We deliberately keep this test data small because we're testing
    # the evidence loader here, not the individual IAM control logic.
    #
    # The evidence includes all fields currently required by:
    # - IAM-01: enabled and mfa_enabled
    # - IAM-02: employment_status and enabled
    # - IAM-03: is_admin and admin_approved
    test_file.write_text(
        'username,first_name,last_name,email_address,department,'
        'employment_status,enabled,mfa_enabled,is_admin,admin_approved\n'
        'jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,'
        'active,true,true,false,false\n'
        'mlopez,Maria,Lopez,mlopez@northstarbuildco.com,Operations,'
        'active,true,false,true,false\n'
    )

    # Load the CSV through our evidence-loading function.
    users = load_user_evidence(test_file)

    # Verify that both user records were loaded.
    assert len(users) == 2

    # Verify that the expected usernames survived the import.
    assert set(users['username']) == {'jcarter', 'mlopez'}

    # Verify that pandas interpreted the enabled column as Boolean data.
    #
    # This matters because our control logic expects True/False rather
    # than arbitrary text such as 'yes', 'active', or 'enabled'.
    assert users['enabled'].dtype == bool

    # Verify the same behavior for MFA status.
    assert users['mfa_enabled'].dtype == bool

    # Verify that the IAM-03 administrative-privilege fields are also
    # interpreted as Boolean data.
    assert users['is_admin'].dtype == bool
    assert users['admin_approved'].dtype == bool



# ============================================================
# USER EVIDENCE SCHEMA VALIDATION TESTS
# ============================================================

def test_load_user_evidence_rejects_missing_required_columns(tmp_path):
    """
    Test that user evidence is rejected when a required column is missing.
    """

    # Create a temporary CSV file for this test.
    test_file = tmp_path / 'users_missing_mfa.csv'

    # This evidence intentionally omits only the 'mfa_enabled' column.
    #
    # All other required fields, including the new IAM-03 fields,
    # are present. This ensures that the test specifically isolates
    # the missing MFA field.
    test_file.write_text(
        'username,first_name,last_name,email_address,department,'
        'employment_status,enabled,is_admin,admin_approved\n'
        'jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,'
        'active,true,false,false\n'
    )

    # The loader should reject incomplete evidence rather than allowing
    # it to proceed into the control-assessment engine.
    #
    # match= also verifies that the error clearly identifies the
    # missing field.
    with pytest.raises(ValueError, match='mfa_enabled'):
        load_user_evidence(test_file)



# ============================================================
# USER EVIDENCE VALUE VALIDATION TESTS
# ============================================================

def test_load_user_evidence_rejects_invalid_boolean_values(tmp_path):
    """
    Test that user evidence is rejected when Boolean fields
    contain unsupported values.
    """

    # Create a temporary CSV containing all required columns.
    #
    # This allows the file to pass schema validation so that this
    # test specifically exercises Boolean-value validation.
    test_file = tmp_path / 'users_invalid_boolean.csv'

    # enabled='active' is intentionally invalid because enabled
    # must contain a Boolean value such as true or false.
    #
    # The remaining Boolean fields contain valid values so that
    # the test isolates the invalid 'enabled' value.
    test_file.write_text(
        'username,first_name,last_name,email_address,department,'
        'employment_status,enabled,mfa_enabled,is_admin,admin_approved\n'
        'jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,'
        'active,active,true,false,false\n'
    )

    # The loader should reject the evidence rather than allowing
    # an unsupported value into the assessment engine.
    #
    # We also require the error message to identify the problematic
    # 'enabled' field.
    with pytest.raises(ValueError, match='enabled'):
        load_user_evidence(test_file)


def test_load_user_evidence_rejects_invalid_employment_status(tmp_path):
    """
    Test that user evidence is rejected when employment_status
    contains an unsupported value.
    """

    # Create a temporary CSV containing all required columns.
    #
    # The record is otherwise valid so that this test specifically
    # exercises employment-status validation.
    test_file = tmp_path / 'users_invalid_employment_status.csv'

    # employment_status='former' is intentionally invalid.
    #
    # Northstar's evidence model currently recognizes:
    # - active
    # - terminated
    # - leave
    #
    # Blank values remain permitted as missing evidence.
    test_file.write_text(
        'username,first_name,last_name,email_address,department,'
        'employment_status,enabled,mfa_enabled,is_admin,admin_approved\n'
        'jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,'
        'former,true,true,false,false\n'
    )

    # The loader should reject an unsupported employment status
    # before the evidence reaches the control-assessment engine.
    #
    # Requiring 'employment_status' in the error message also makes
    # the validation failure easier for an analyst to diagnose.
    with pytest.raises(ValueError, match='employment_status'):
        load_user_evidence(test_file)



# ============================================================
# DEVICE EVIDENCE TESTS
# ============================================================

def test_load_device_evidence(tmp_path):
    """
    Test that device evidence can be loaded from a CSV file.
    """

    # Create a temporary device-evidence CSV.
    #
    # Using tmp_path keeps this unit test independent from the real
    # data/devices.csv file used by the Control Assurance Engine.
    test_file = tmp_path / 'devices.csv'

    # Create two representative endpoint records.
    #
    # The first device is encrypted and protected.
    # The second device is not encrypted but still has endpoint
    # protection enabled.
    #
    # At this stage, we are testing evidence ingestion only.
    # Whether DEV-002 violates a control will be tested separately
    # when we build END-01.
    test_file.write_text(
        'device_id,device_name,assigned_user,device_type,'
        'operating_system,company_managed,disk_encrypted,'
        'endpoint_protection\n'
        'DEV-001,NS-LT-001,jcarter,laptop,Windows 11 Pro,'
        'true,true,true\n'
        'DEV-002,NS-LT-002,mlopez,laptop,Windows 11 Pro,'
        'true,false,true\n'
    )

    # Load the CSV through the device-evidence loader.
    devices = load_device_evidence(test_file)

    # Verify that both device records were loaded.
    assert len(devices) == 2

    # Verify that the expected device identifiers survived
    # the import.
    assert set(devices['device_id']) == {
        'DEV-001',
        'DEV-002'
    }

    # Verify that the control-relevant device fields are loaded
    # as Boolean data rather than arbitrary strings.
    assert devices['company_managed'].dtype == bool
    assert devices['disk_encrypted'].dtype == bool
    assert devices['endpoint_protection'].dtype == bool



# ============================================================
# DEVICE EVIDENCE SCHEMA VALIDATION TESTS
# ============================================================

def test_load_device_evidence_rejects_missing_required_columns(tmp_path):
    """
    Test that device evidence is rejected when a required
    column is missing.
    """

    # Create a temporary device-evidence CSV.
    test_file = tmp_path / 'devices_missing_encryption.csv'

    # This evidence intentionally omits only the 'disk_encrypted'
    # column.
    #
    # All other required fields are present so that this test
    # specifically isolates the missing encryption field.
    test_file.write_text(
        'device_id,device_name,assigned_user,device_type,'
        'operating_system,company_managed,endpoint_protection\n'
        'DEV-001,NS-LT-001,jcarter,laptop,Windows 11 Pro,'
        'true,true\n'
    )

    # The loader should reject incomplete endpoint evidence
    # before it reaches the control-assessment engine.
    #
    # Requiring 'disk_encrypted' in the error message makes the
    # validation failure clear to the analyst.
    with pytest.raises(ValueError, match='disk_encrypted'):
        load_device_evidence(test_file)



# ============================================================
# DEVICE EVIDENCE VALUE VALIDATION TESTS
# ============================================================

def test_load_device_evidence_rejects_invalid_boolean_values(tmp_path):
    """
    Test that device evidence is rejected when Boolean fields
    contain unsupported values.
    """

    # Create a temporary CSV containing all required device columns.
    #
    # This allows the evidence to pass schema validation so that
    # this test specifically exercises Boolean-value validation.
    test_file = tmp_path / 'devices_invalid_boolean.csv'

    # disk_encrypted='yes' is intentionally invalid.
    #
    # The engine expects Boolean evidence such as true or false.
    # Values such as 'yes', 'encrypted', or 'enabled' should not
    # silently enter the control-assessment pipeline.
    test_file.write_text(
        'device_id,device_name,assigned_user,device_type,'
        'operating_system,company_managed,disk_encrypted,'
        'endpoint_protection\n'
        'DEV-001,NS-LT-001,jcarter,laptop,Windows 11 Pro,'
        'true,yes,true\n'
    )

    # The loader should reject the malformed evidence.
    #
    # We also require the error message to identify the
    # problematic disk_encrypted field.
    with pytest.raises(ValueError, match='disk_encrypted'):
        load_device_evidence(test_file)



# ============================================================
# VENDOR EVIDENCE TESTS
# ============================================================

def test_load_vendor_evidence():
    """
    Test that valid vendor evidence is loaded successfully
    with the expected columns and records.
    """

    # Load the Northstar BuildCo vendor evidence file.
    vendors = load_vendor_evidence('data/vendors.csv')

    # Verify that all seven vendor records were loaded.
    assert len(vendors) == 7

    # Verify that the expected vendor evidence fields exist.
    assert list(vendors.columns) == [
        'vendor_id',
        'vendor_name',
        'service_type',
        'critical_vendor',
        'security_review_completed',
        'review_date'
    ]

    # Verify a representative vendor record so that the test
    # checks actual evidence values rather than only structure.
    apex_it = vendors[
        vendors['vendor_id'] == 'VND-001'
    ].iloc[0]

    assert apex_it['vendor_name'] == 'Apex IT Services'
    assert apex_it['critical_vendor'] == True
    assert apex_it['security_review_completed'] == True



# ============================================================
# VENDOR EVIDENCE SCHEMA VALIDATION TESTS
# ============================================================

def test_load_vendor_evidence_rejects_missing_required_columns(tmp_path):
    """
    Test that vendor evidence is rejected when a required
    column is missing.
    """

    # Create a temporary vendor-evidence CSV.
    test_file = tmp_path / 'vendors_missing_security_review.csv'

    # This evidence intentionally omits only the
    # 'security_review_completed' column.
    #
    # All other required vendor fields are present so that
    # this test specifically isolates the missing security
    # review field.
    test_file.write_text(
        'vendor_id,vendor_name,service_type,critical_vendor,review_date\n'
        'VND-001,Apex IT Services,Managed Service Provider,true,2026-06-15\n'
    )

    # The loader should reject incomplete vendor evidence
    # before it reaches the control-assessment engine.
    #
    # Requiring 'security_review_completed' in the error
    # message also makes the validation failure clear
    # to the analyst.
    with pytest.raises(
        ValueError,
        match='security_review_completed'
    ):
        load_vendor_evidence(test_file)



# ============================================================
# VENDOR EVIDENCE VALUE VALIDATION TESTS
# ============================================================

def test_load_vendor_evidence_rejects_invalid_boolean_values(tmp_path):
    """
    Test that vendor evidence is rejected when Boolean fields
    contain unsupported values.
    """

    # Create a temporary CSV containing all required vendor columns.
    #
    # This allows the evidence to pass schema validation so that
    # this test specifically exercises Boolean-value validation.
    test_file = tmp_path / 'vendors_invalid_boolean.csv'

    # critical_vendor='yes' is intentionally invalid.
    #
    # The engine expects Boolean evidence such as true or false.
    # The security_review_completed field contains a valid value
    # so that this test isolates the critical_vendor field.
    test_file.write_text(
        'vendor_id,vendor_name,service_type,critical_vendor,'
        'security_review_completed,review_date\n'
        'VND-001,Apex IT Services,Managed Service Provider,'
        'yes,true,2026-06-15\n'
    )

    # The loader should reject the malformed vendor evidence
    # rather than allowing an ambiguous value into the
    # control-assessment engine.
    #
    # Requiring 'critical_vendor' in the error message makes
    # the validation failure easier for an analyst to diagnose.
    with pytest.raises(
        ValueError,
        match='critical_vendor'
    ):
        load_vendor_evidence(test_file)


def test_load_vendor_evidence_rejects_invalid_security_review_value(tmp_path):
    """
    Test that vendor evidence is rejected when
    security_review_completed contains an unsupported value.
    """

    # Create a temporary CSV containing all required vendor columns.
    #
    # critical_vendor is deliberately valid so that this test
    # specifically exercises security_review_completed validation.
    test_file = tmp_path / 'vendors_invalid_security_review.csv'

    # security_review_completed='completed' is intentionally invalid.
    #
    # The field must contain Boolean evidence such as true or false,
    # or remain blank when the evidence is missing.
    test_file.write_text(
        'vendor_id,vendor_name,service_type,critical_vendor,'
        'security_review_completed,review_date\n'
        'VND-001,Apex IT Services,Managed Service Provider,'
        'true,completed,2026-06-15\n'
    )

    # The loader should reject the malformed value and identify
    # the field responsible for the validation failure.
    with pytest.raises(
        ValueError,
        match='security_review_completed'
    ):
        load_vendor_evidence(test_file)



