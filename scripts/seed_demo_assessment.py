"""Generate fictional assessment data for workspace demonstrations."""

from datetime import date

from src.assessment_models import (
    Assessment,
    ControlAssessment,
    Finding,
)
from src.assessment_service import create_assessment
from src.control_catalog import CONTROL_CATALOG


def main() -> None:
    """Create a fictional assessment for workspace demonstrations."""

    assessment = Assessment(
        assessment_id="ASM-DEMO-001",
        organization="Northstar BuildCo",
        assessor="Demo Security Assessor",
        assessment_date=date(2026, 10, 5),
        framework="NIST CSF 2.0",
        scope=(
            "Identity and Access Management, Endpoint Security, and Third-Party Risk"
        ),
    )

    control_assessments = [
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="IAM-01",
            assessment_method="AUTOMATED",
            implementation_status="PARTIALLY_IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/users.csv"],
            observations=(
                "Three active user accounts were identified "
                "without MFA enabled: mlopez, jparis, snguyen."
            ),
        ),
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="IAM-02",
            assessment_method="AUTOMATED",
            implementation_status="PARTIALLY_IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/users.csv"],
            observations=(
                "One terminated employee account remained enabled: malvarez."
            ),
        ),
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="IAM-03",
            assessment_method="AUTOMATED",
            implementation_status="PARTIALLY_IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/users.csv"],
            observations=(
                "Administrative privileges were identified "
                "without documented approval for account akim."
            ),
        ),
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="END-01",
            assessment_method="AUTOMATED",
            implementation_status="PARTIALLY_IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/devices.csv"],
            observations=(
                "Two company-managed endpoints were identified "
                "without disk encryption: DEV-002 and DEV-005."
            ),
        ),
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="END-02",
            assessment_method="AUTOMATED",
            implementation_status="IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/devices.csv"],
            observations=(
                "No endpoint protection exceptions were identified "
                "among the evaluated company-managed devices."
            ),
        ),
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="TPR-01",
            assessment_method="AUTOMATED",
            implementation_status="PARTIALLY_IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/vendors.csv"],
            observations=(
                "Critical vendor VND-003 was identified "
                "without a documented security review."
            ),
        ),
        ControlAssessment(
            assessment_id=assessment.assessment_id,
            control_id="TPR-02",
            assessment_method="AUTOMATED",
            implementation_status="PARTIALLY_IMPLEMENTED",
            evidence_status="SUFFICIENT",
            evidence_references=["data/vendors.csv"],
            observations=("Vendor VND-002 had privileged access without MFA enabled."),
        ),
    ]

    failed_control_ids = (
        "IAM-01",
        "IAM-02",
        "IAM-03",
        "END-01",
        "TPR-01",
        "TPR-02",
    )

    findings = []

    for index, control_id in enumerate(failed_control_ids, start=1):
        control = CONTROL_CATALOG[control_id]

        finding = Finding(
            finding_id=f"FND-DEMO-{index:03d}",
            assessment_id=assessment.assessment_id,
            control_id=control_id,
            description=control["finding_description"],
            likelihood=control["likelihood"],
            impact=control["impact"],
            risk_rationale=(
                "Confirmed control deficiency identified during "
                "the Northstar BuildCo assessment."
            ),
            recommendation=control["recommendation"],
        )

        findings.append(finding)

    saved_path = create_assessment(
        assessment=assessment,
        control_assessments=control_assessments,
        findings=findings,
    )

    print(f"Demonstration assessment saved to: {saved_path}")


if __name__ == "__main__":
    main()
