"""Tests for loading and validating assessment evidence."""

import pytest

from src.evidence import load_device_evidence, load_user_evidence, load_vendor_evidence

# User evidence tests


def test_load_user_evidence(tmp_path):
    """Verify that user evidence can be loaded from a CSV file."""
    test_file = tmp_path / "users.csv"

    # Include the evidence fields required by IAM-01, IAM-02, and IAM-03.
    test_file.write_text(
        "username,first_name,last_name,email_address,department,"
        "employment_status,enabled,mfa_enabled,is_admin,admin_approved\n"
        "jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,"
        "active,true,true,false,false\n"
        "mlopez,Maria,Lopez,mlopez@northstarbuildco.com,Operations,"
        "active,true,false,true,false\n"
    )

    users = load_user_evidence(test_file)

    assert len(users) == 2

    assert set(users["username"]) == {"jcarter", "mlopez"}

    # Boolean evidence must be parsed as Boolean data, not free-form text.
    assert users["enabled"].dtype == bool

    assert users["mfa_enabled"].dtype == bool

    assert users["is_admin"].dtype == bool
    assert users["admin_approved"].dtype == bool


# User evidence schema validation


def test_load_user_evidence_rejects_missing_required_columns(tmp_path):
    """Reject user evidence that omits a required column."""
    test_file = tmp_path / "users_missing_mfa.csv"

    # Omit only mfa_enabled to isolate the missing-column validation.
    test_file.write_text(
        "username,first_name,last_name,email_address,department,"
        "employment_status,enabled,is_admin,admin_approved\n"
        "jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,"
        "active,true,false,false\n"
    )

    with pytest.raises(ValueError, match="mfa_enabled"):
        load_user_evidence(test_file)


# User evidence value validation


def test_load_user_evidence_rejects_invalid_boolean_values(tmp_path):
    """Reject user evidence with unsupported Boolean values."""
    test_file = tmp_path / "users_invalid_boolean.csv"

    # Keep other fields valid so the test isolates enabled='active'.
    test_file.write_text(
        "username,first_name,last_name,email_address,department,"
        "employment_status,enabled,mfa_enabled,is_admin,admin_approved\n"
        "jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,"
        "active,active,true,false,false\n"
    )

    with pytest.raises(ValueError, match="enabled"):
        load_user_evidence(test_file)


def test_load_user_evidence_rejects_invalid_employment_status(tmp_path):
    """Reject user evidence with an unsupported employment status."""
    test_file = tmp_path / "users_invalid_employment_status.csv"

    # Supported statuses are active, terminated, and leave; blank values
    # remain valid as missing evidence. "former" is intentionally invalid.
    test_file.write_text(
        "username,first_name,last_name,email_address,department,"
        "employment_status,enabled,mfa_enabled,is_admin,admin_approved\n"
        "jcarter,James,Carter,jcarter@northstarbuildco.com,Finance,"
        "former,true,true,false,false\n"
    )

    with pytest.raises(ValueError, match="employment_status"):
        load_user_evidence(test_file)


# Device evidence tests


def test_load_device_evidence(tmp_path):
    """Verify that device evidence can be loaded from a CSV file."""
    test_file = tmp_path / "devices.csv"

    # Test evidence ingestion independently from END-01 assessment logic.
    test_file.write_text(
        "device_id,device_name,assigned_user,device_type,"
        "operating_system,company_managed,disk_encrypted,"
        "endpoint_protection\n"
        "DEV-001,NS-LT-001,jcarter,laptop,Windows 11 Pro,"
        "true,true,true\n"
        "DEV-002,NS-LT-002,mlopez,laptop,Windows 11 Pro,"
        "true,false,true\n"
    )

    devices = load_device_evidence(test_file)

    assert len(devices) == 2

    assert set(devices["device_id"]) == {"DEV-001", "DEV-002"}

    assert devices["company_managed"].dtype == bool
    assert devices["disk_encrypted"].dtype == bool
    assert devices["endpoint_protection"].dtype == bool


# Device evidence schema validation


def test_load_device_evidence_rejects_missing_required_columns(tmp_path):
    """Reject device evidence that omits a required column."""
    test_file = tmp_path / "devices_missing_encryption.csv"

    # Omit only disk_encrypted to isolate the missing-column validation.
    test_file.write_text(
        "device_id,device_name,assigned_user,device_type,"
        "operating_system,company_managed,endpoint_protection\n"
        "DEV-001,NS-LT-001,jcarter,laptop,Windows 11 Pro,"
        "true,true\n"
    )

    with pytest.raises(ValueError, match="disk_encrypted"):
        load_device_evidence(test_file)


# Device evidence value validation


def test_load_device_evidence_rejects_invalid_boolean_values(tmp_path):
    """Reject device evidence with unsupported Boolean values."""
    test_file = tmp_path / "devices_invalid_boolean.csv"

    # "yes" is not valid Boolean evidence; the other fields are valid.
    test_file.write_text(
        "device_id,device_name,assigned_user,device_type,"
        "operating_system,company_managed,disk_encrypted,"
        "endpoint_protection\n"
        "DEV-001,NS-LT-001,jcarter,laptop,Windows 11 Pro,"
        "true,yes,true\n"
    )

    with pytest.raises(ValueError, match="disk_encrypted"):
        load_device_evidence(test_file)


# Vendor evidence tests


def test_load_vendor_evidence():
    """Verify that vendor evidence loads with the expected schema and records."""
    vendors = load_vendor_evidence("data/vendors.csv")

    assert len(vendors) == 7

    assert list(vendors.columns) == [
        "vendor_id",
        "vendor_name",
        "service_type",
        "critical_vendor",
        "security_review_completed",
        "review_date",
        "privileged_access",
        "mfa_enabled",
    ]

    # Check a representative record in addition to the file schema.
    apex_it = vendors[vendors["vendor_id"] == "VND-001"].iloc[0]

    assert apex_it["vendor_name"] == "Apex IT Services"
    assert apex_it["critical_vendor"] == True
    assert apex_it["security_review_completed"] == True


# Vendor evidence schema validation


def test_load_vendor_evidence_rejects_missing_required_columns(tmp_path):
    """Reject vendor evidence that omits a required column."""
    test_file = tmp_path / "vendors_missing_security_review.csv"

    # Omit only security_review_completed to isolate this schema error.
    test_file.write_text(
        "vendor_id,vendor_name,service_type,critical_vendor,review_date\n"
        "VND-001,Apex IT Services,Managed Service Provider,true,2026-06-15\n"
    )

    with pytest.raises(ValueError, match="security_review_completed"):
        load_vendor_evidence(test_file)


# Vendor evidence value validation


def test_load_vendor_evidence_rejects_invalid_boolean_values(tmp_path):
    """Reject vendor evidence with unsupported Boolean values."""
    test_file = tmp_path / "vendors_invalid_boolean.csv"

    # Keep the other Boolean field valid to isolate critical_vendor='yes'.
    test_file.write_text(
        "vendor_id,vendor_name,service_type,critical_vendor,"
        "security_review_completed,review_date,"
        "privileged_access,mfa_enabled\n"
        "VND-001,Apex IT Services,Managed Service Provider,"
        "yes,true,2026-06-15,true,true\n"
    )

    with pytest.raises(ValueError, match="critical_vendor"):
        load_vendor_evidence(test_file)


def test_load_vendor_evidence_rejects_invalid_security_review_value(tmp_path):
    """Reject unsupported security-review status values."""
    test_file = tmp_path / "vendors_invalid_security_review.csv"

    # The field accepts Boolean values or blank missing evidence.
    test_file.write_text(
        "vendor_id,vendor_name,service_type,critical_vendor,"
        "security_review_completed,review_date,"
        "privileged_access,mfa_enabled\n"
        "VND-001,Apex IT Services,Managed Service Provider,"
        "true,completed,2026-06-15,true,true\n"
    )

    with pytest.raises(ValueError, match="security_review_completed"):
        load_vendor_evidence(test_file)


def test_load_vendor_evidence_rejects_invalid_privileged_access_value(tmp_path):
    """Reject unsupported privileged-access values."""
    test_file = tmp_path / "vendors_invalid_privileged_access.csv"

    test_file.write_text(
        "vendor_id,vendor_name,service_type,critical_vendor,"
        "security_review_completed,review_date,"
        "privileged_access,mfa_enabled\n"
        "VND-001,Apex IT Services,Managed Service Provider,"
        "true,true,2026-06-15,yes,true\n"
    )

    with pytest.raises(ValueError, match="privileged_access"):
        load_vendor_evidence(test_file)


def test_load_vendor_evidence_rejects_invalid_mfa_enabled_value(tmp_path):
    """Reject unsupported MFA status values."""
    test_file = tmp_path / "vendors_invalid_mfa_enabled.csv"

    test_file.write_text(
        "vendor_id,vendor_name,service_type,critical_vendor,"
        "security_review_completed,review_date,"
        "privileged_access,mfa_enabled\n"
        "VND-001,Apex IT Services,Managed Service Provider,"
        "true,true,2026-06-15,true,enabled\n"
    )

    with pytest.raises(ValueError, match="mfa_enabled"):
        load_vendor_evidence(test_file)
