# Control Assurance Engine

A Python-based cybersecurity GRC assessment tool that evaluates structured security evidence against defined controls, identifies control exceptions and evidence-quality issues, maps findings to the NIST Cybersecurity Framework (CSF) 2.0, assigns risk severity, and produces analyst- and management-facing reports.

The project models a control assurance assessment for **Northstar BuildCo**, a fictional construction company with approximately 75 employees. The assessment evaluates selected controls across Identity and Access Management, Endpoint Security, and Third-Party Risk using representative user, device, and vendor evidence.

## Project Purpose

Traditional control assessments often require analysts to manually review evidence, determine whether records are in scope, identify exceptions, document findings, and summarize results for management. This project demonstrates how portions of that workflow can be standardized and automated while preserving important GRC distinctions between:

- a confirmed control exception,
- incomplete or insufficient evidence,
- an out-of-scope record, and
- a control that cannot be assessed.

The engine is designed to produce repeatable control-testing results without treating missing evidence as automatic control failure or assuming that a control passes when there is no assessable population.

## How It Works

The Control Assurance Engine separates evidence handling, control logic, risk evaluation, and reporting into distinct stages:

```text
Security Evidence
      ↓
Schema & Value Validation
      ↓
Control-Specific Assessment
      ↓
Structured GRC Findings
      ↓
NIST CSF 2.0 Mapping
      ↓
Risk Scoring & Severity
      ↓
Executive & Remediation Reporting
      ↓
CSV and Markdown Outputs
```

## Assessment Scope & Controls

Version 1 evaluates seven cybersecurity controls across three control domains. Each control uses a defined evidence source and applies its own scope and evidence-sufficiency logic.

| Control | Domain | Requirement | Evidence Source |
| --- | --- | --- | --- |
| IAM-01 | Identity and Access Management | Active user accounts must have MFA enabled | `users.csv` |
| IAM-02 | Identity and Access Management | Terminated user accounts must be disabled | `users.csv` |
| IAM-03 | Identity and Access Management | Administrative privileges must be limited to approved accounts | `users.csv` |
| END-01 | Endpoint Security | Company-managed endpoints must use disk encryption | `devices.csv` |
| END-02 | Endpoint Security | Company-managed endpoints must have endpoint protection enabled | `devices.csv` |
| TPR-01 | Third-Party Risk | Critical third-party vendors must have a documented security review | `vendors.csv` |
| TPR-02 | Third-Party Risk | Third-party vendors with privileged access must use MFA | `vendors.csv` |

### Control Results

A control assessment produces one of three results:

- **PASS** — An assessable population exists and no confirmed exceptions were identified.
- **FAIL** — One or more confirmed control exceptions were identified within the assessable population.
- **NOT ASSESSED** — No assessable population exists, so the engine does not infer that the control passed.

Evidence issues are tracked independently from the control result. For example, if a required field is missing for an otherwise in-scope record and the missing value prevents the control from being evaluated, the record is classified as an evidence issue rather than automatically treated as a control exception.

## Outputs & Example Results

Running the assessment produces two complementary deliverables.

### Structured Findings

[`output/control_findings.csv`](output/control_findings.csv) contains the structured results of the control assessment for further analysis, filtering, or integration with other reporting workflows.

The output includes information such as:

- control identifier and requirement,
- assessment result,
- population tested,
- exception count and rate,
- affected entities,
- evidence issues,
- NIST CSF 2.0 mapping,
- likelihood and impact,
- risk score and severity, and
- management-oriented finding and remediation information.

### Management Report

[`output/management_report.md`](output/management_report.md) converts the structured assessment results into a management-facing cybersecurity control assurance report.

The report includes:

- assessment scope and framework alignment,
- executive-level assessment metrics,
- a narrative interpretation of the results, and
- remediation-focused findings for confirmed control failures.

### Sample Assessment Results

Using the included synthetic Northstar BuildCo evidence, the assessment produces:

| Metric | Result |
| --- | ---: |
| Controls Evaluated | 7 |
| Passed | 1 |
| Failed | 6 |
| Not Assessed | 0 |
| Total Exceptions | 9 |
| Evidence Issues | 7 |
| High Findings | 6 |
| Critical Findings | 0 |

Six of seven controls evaluated resulted in confirmed exceptions requiring remediation. No Critical-severity findings were identified; six findings were rated High using the scenario-specific Northstar BuildCo risk criteria.

The purpose of the sample results is to demonstrate the assessment engine's behavior across different evidence and control conditions. They should not be interpreted as findings about a real organization.

### Example Finding

A failed control is presented to management with the control identifier, severity, finding context, affected entities, and recommended remediation:

```text
IAM-01 | HIGH

Finding:
Active user accounts were identified without MFA enabled,
increasing the risk of unauthorized access if credentials
are compromised.

Affected:
mlopez, jparis, snguyen

Recommendation:
Enable MFA for all active user accounts and verify enrollment.
```

## NIST CSF 2.0 Alignment & Risk Methodology

### NIST CSF 2.0 Alignment

Each control in the assessment catalog is mapped to a relevant NIST Cybersecurity Framework (CSF) 2.0 function, category, and subcategory.

The mappings provide a recognized framework reference for the control objective and help connect individual assessment findings to broader cybersecurity outcomes. They are used for control alignment and reporting context; they do not represent a claim of NIST CSF certification or comprehensive framework coverage.

Examples include:

| Control | NIST Function | Category | Subcategory |
| --- | --- | --- | --- |
| IAM-01 | Protect | PR.AA — Identity Management, Authentication, and Access Control | PR.AA-03 |
| IAM-02 | Protect | PR.AA — Identity Management, Authentication, and Access Control | PR.AA-05 |
| IAM-03 | Protect | PR.AA — Identity Management, Authentication, and Access Control | PR.AA-05 |
| END-01 | Protect | PR.DS — Data Security | PR.DS-01 |
| END-02 | Protect | PR.PS — Platform Security | PR.PS-05 |
| TPR-01 | Govern | GV.SC — Cybersecurity Supply Chain Risk Management | GV.SC-07 |
| TPR-02 | Protect | PR.AA — Identity Management, Authentication, and Access Control | PR.AA-03 |

### Risk Methodology

Risk is evaluated separately from control performance.

For each failed control, the engine uses predefined **likelihood** and **impact** values representing the risk scenario associated with that control. Both values use a 1–5 scale.

The risk score is calculated as:

`Risk Score = Likelihood × Impact`

Scores are classified using the following model:

| Risk Score | Severity |
| ---: | --- |
| 1–4 | Low |
| 5–9 | Moderate |
| 10–16 | High |
| 17–25 | Critical |

Risk severity is assigned only to confirmed failed controls. Controls that pass or are not assessed do not receive an active finding severity.

The likelihood and impact values used in this project are scenario-specific assumptions for the fictional Northstar BuildCo assessment. They are not prescribed by NIST CSF 2.0.

### Why Exception Rate Does Not Determine Risk

The engine intentionally does not derive risk severity directly from exception rate.

Exception rate measures the frequency of observed control deficiencies within the assessable population, while risk severity considers the potential significance of the underlying scenario. A small number of exceptions can therefore represent substantial risk.

For example, one unauthorized administrative account may present greater security risk than several lower-impact control exceptions. Keeping control performance and risk evaluation separate avoids treating frequency as a substitute for business or security impact.

## Evidence Model & Sample Data

The assessment uses three structured CSV evidence sources representing common data that may be collected during a cybersecurity control review.

### User Evidence

`data/users.csv` contains identity and account information used by the IAM controls, including:

- employment status,
- account enabled status,
- MFA status,
- administrative privilege status, and
- administrative approval status.

This evidence supports testing for MFA coverage, terminated-account deactivation, and approved privileged access.

### Device Evidence

`data/devices.csv` contains endpoint information used by the Endpoint Security controls, including:

- device identifier and assigned user,
- device type and operating system,
- company-managed status,
- disk-encryption status, and
- endpoint-protection status.

This evidence supports testing whether company-managed endpoints meet defined encryption and endpoint-protection requirements.

### Vendor Evidence

`data/vendors.csv` contains third-party information used by the Third-Party Risk controls, including:

- vendor and service information,
- critical-vendor designation,
- security-review status,
- review date,
- privileged-access status, and
- MFA status.

This evidence supports testing security-review requirements for critical vendors and MFA requirements for vendors with privileged access.

### Deliberate Evidence Conditions

The sample evidence includes a mixture of:

- compliant records,
- confirmed control exceptions,
- incomplete evidence,
- records outside a particular control's scope, and
- supporting information that should not independently determine compliance.

These conditions are intentional. They allow the engine to demonstrate the difference between **control scope**, **evidence sufficiency**, and **control compliance**.

For example, an unmanaged personal device is outside the scope of controls that apply specifically to company-managed endpoints. Its lack of disk encryption therefore does not automatically create an END-01 exception.

Similarly, a critical vendor with an unknown security-review status is treated as an evidence issue rather than a failed review. The presence of a review date alone is not used to infer that the required security review was completed.

### Control-Specific Evidence Sufficiency

Evidence sufficiency is evaluated at the individual-control level rather than globally.

A missing value is considered an evidence issue only when it prevents the engine from determining control scope or evaluating an in-scope record. This means the same missing field may be significant for one control while being irrelevant to another.

This design reflects a central principle of the project:

> **Missing evidence is not the same as evidence of control failure.**

## Design Principles & Key Decisions

The Control Assurance Engine was designed around several principles intended to preserve meaningful distinctions that arise during real control assessments.

### 1. Missing Evidence Is Not a Control Failure

The engine distinguishes between evidence that demonstrates noncompliance and evidence that is insufficient to reach a conclusion.

If information required to assess an in-scope record is missing, the record is classified as an **evidence issue** rather than automatically treated as a control exception.

This prevents uncertainty from being represented as confirmed control failure.

### 2. Assessability Is Control-Specific

Evidence is not classified as globally complete or incomplete.

Each control independently determines:

1. whether a record is in scope,
2. whether sufficient evidence exists to assess it, and
3. whether the assessable record satisfies the control requirement.

For example, a missing MFA value may matter when evaluating an active user under IAM-01 but may have no relevance to a control testing terminated-account deactivation.

### 3. No Assessable Population Does Not Equal PASS

A control with zero assessable records is classified as **NOT ASSESSED**, not PASS.

A PASS result requires an assessable population in which no confirmed exceptions were identified. This prevents absence of evidence from being interpreted as evidence of effective control operation.

### 4. Scope Is Evaluated Before Compliance

Records outside a control's defined scope do not create exceptions simply because they would fail the control condition if evaluated.

For example, an unmanaged personal endpoint is outside the scope of a control requiring disk encryption on company-managed devices. Its encryption status therefore does not affect the END-01 result.

### 5. Supporting Evidence Does Not Automatically Prove Compliance

The engine avoids inferring control compliance from related data when the required control evidence is unavailable.

For example, the presence of a vendor security-review date does not independently prove that a documented security review was completed when the review-status field is unknown.

### 6. Control Performance and Risk Are Separate

Control exceptions describe observed control performance. Risk severity describes the significance of the associated risk scenario.

The engine therefore does not calculate finding severity directly from exception count or exception rate. Failed controls receive predefined likelihood and impact assumptions appropriate to the modeled Northstar BuildCo scenario.

### 7. Framework Mapping and Risk Scoring Serve Different Purposes

NIST CSF 2.0 mappings provide framework alignment for control objectives and findings.

Likelihood, impact, risk scores, and severity classifications are separate assessment constructs defined for this project. The engine does not present its risk methodology as a NIST-prescribed scoring model.

### 8. Assessment Logic Is Separated From Presentation

The project separates:

- evidence ingestion and validation,
- control assessment,
- control metadata,
- risk calculation,
- structured finding construction,
- management formatting, and
- file export.

This separation allows assessment logic to be tested independently from presentation and makes it easier to extend individual components without changing unrelated parts of the workflow.

### 9. Reporting Serves Different Audiences

The engine produces both structured and management-facing outputs.

`control_findings.csv` preserves detailed assessment data for analysis and downstream processing, while `management_report.md` presents executive metrics and confirmed remediation findings in a more concise format.

This avoids forcing one report format to serve both technical analysis and management communication.

## Project Structure

```text
control-assurance-engine/
├── data/
│   ├── users.csv
│   ├── devices.csv
│   └── vendors.csv
├── output/
│   ├── control_findings.csv
│   └── management_report.md
├── src/
│   ├── control_catalog.py
│   ├── controls.py
│   ├── evidence.py
│   ├── main.py
│   ├── reporting.py
│   └── risk.py
├── tests/
│   ├── test_control_catalog.py
│   ├── test_controls.py
│   ├── test_evidence.py
│   ├── test_reporting.py
│   └── test_risk.py
├── .gitignore
├── README.md
└── requirements.txt
```

### Input Evidence Schema

The engine expects three CSV evidence files with predefined column schemas. Required columns must be present for evidence ingestion to succeed; however, some individual field values may be blank.

This distinction is intentional. A **required column** defines the structure expected from the evidence source, while a **nullable value** allows the control-assessment logic to determine whether missing information constitutes an evidence issue for a particular control.

Boolean evidence fields use `true` and `false`. Where null values are permitted, a blank CSV value represents unavailable or missing evidence.

#### User Evidence Schema — `data/users.csv`

| Field | Type | Required Column | Null Allowed | Description |
| --- | --- | :---: | :---: | --- |
| `username` | String | Yes | No* | User account identifier |
| `first_name` | String | Yes | No* | User's first name |
| `last_name` | String | Yes | No* | User's last name |
| `email_address` | String | Yes | No* | User's email address |
| `department` | String | Yes | No* | Organizational department |
| `employment_status` | String | Yes | Yes | Employment status: `active`, `terminated`, or `leave` |
| `enabled` | Boolean | Yes | Yes | Whether the user account is enabled |
| `mfa_enabled` | Boolean | Yes | Yes | Whether MFA is enabled for the account |
| `is_admin` | Boolean | Yes | Yes | Whether the account has administrative privileges |
| `admin_approved` | Boolean | Yes | Yes | Whether administrative privileges have documented approval |

\* Version 1 requires these columns to exist but does not currently perform explicit null-value validation on these descriptive identity fields.

The IAM controls use the evidence fields differently depending on the control being evaluated:

- **IAM-01** uses `enabled` and `mfa_enabled` to evaluate MFA for active accounts.
- **IAM-02** uses `employment_status` and `enabled` to evaluate account deactivation for terminated users.
- **IAM-03** uses `is_admin` and `admin_approved` to evaluate authorization of administrative privileges.

A missing value is therefore not automatically an evidence issue for every IAM control. Its significance depends on whether the field is required to determine scope or evaluate an in-scope record for that specific control.

#### Device Evidence Schema — `data/devices.csv`

| Field | Type | Required Column | Null Allowed | Description |
| --- | --- | :---: | :---: | --- |
| `device_id` | String | Yes | No* | Unique device identifier |
| `device_name` | String | Yes | No* | Device hostname or descriptive name |
| `assigned_user` | String | Yes | No* | User associated with the device |
| `device_type` | String | Yes | No* | Device classification, such as laptop or desktop |
| `operating_system` | String | Yes | No* | Operating system installed on the device |
| `company_managed` | Boolean | Yes | Yes | Whether the device is managed by the organization |
| `disk_encrypted` | Boolean | Yes | Yes | Whether disk encryption is enabled |
| `endpoint_protection` | Boolean | Yes | Yes | Whether endpoint protection is enabled |

\* Version 1 requires these columns to exist but does not currently perform explicit null-value validation on these descriptive device fields.

The Endpoint Security controls use `company_managed` to determine whether a device falls within the control scope:

- **END-01** evaluates `disk_encrypted` for company-managed devices.
- **END-02** evaluates `endpoint_protection` for company-managed devices.

If `company_managed` is missing, the engine cannot determine whether the device is in scope, so the record becomes an evidence issue for the applicable endpoint control.

If a device is confirmed as company-managed but the control-specific security field is missing, the record is also treated as an evidence issue because compliance cannot be determined.

Conversely, a device explicitly identified as unmanaged is outside the scope of these controls. Missing or noncompliant encryption or endpoint-protection values on that device do not create control exceptions.

#### Vendor Evidence Schema — `data/vendors.csv`

| Field | Type | Required Column | Null Allowed | Description |
| --- | --- | :---: | :---: | --- |
| `vendor_id` | String | Yes | No* | Unique vendor identifier |
| `vendor_name` | String | Yes | No* | Vendor or third-party name |
| `service_type` | String | Yes | No* | Type of service provided by the vendor |
| `critical_vendor` | Boolean | Yes | Yes | Whether the vendor is classified as critical |
| `security_review_completed` | Boolean | Yes | Yes | Whether a documented security review has been completed |
| `review_date` | String | Yes | Yes | Date associated with the documented security review |
| `privileged_access` | Boolean | Yes | Yes | Whether the vendor has privileged access to organizational systems or resources |
| `mfa_enabled` | Boolean | Yes | Yes | Whether MFA is enabled for the vendor's privileged access |

\* Version 1 requires these columns to exist but does not currently perform explicit null-value validation on these descriptive vendor fields.

The Third-Party Risk controls use different vendor attributes to determine scope:

- **TPR-01** uses `critical_vendor` to determine scope and evaluates `security_review_completed` for critical vendors.
- **TPR-02** uses `privileged_access` to determine scope and evaluates `mfa_enabled` for vendors with privileged access.

For TPR-01, `review_date` is treated as supporting evidence only. The presence of a review date does not independently establish that a documented security review was completed. If `security_review_completed` is missing for a critical vendor, the record is classified as an evidence issue even when `review_date` contains a value.

Similarly, a vendor confirmed not to have privileged access is outside the scope of TPR-02. A missing or false MFA value for that vendor does not create a TPR-02 control exception.

#### Input Validation Summary

Version 1 applies two levels of evidence handling:

1. **Ingestion validation** verifies that all required columns are present and that validated fields contain supported values. Unsupported Boolean or employment-status values cause evidence loading to fail.

2. **Control-specific assessment** determines whether individual records are in scope, whether sufficient evidence exists to assess them, and whether assessable records satisfy the applicable control requirement.

This separation allows incomplete evidence to be processed when the missing information itself is relevant to the assessment, while preventing malformed or unsupported evidence values from silently affecting control results.

### Key Components

- **`src/evidence.py`** — Loads evidence files and validates required schemas and supported values.
- **`src/controls.py`** — Contains control-specific scope, assessability, and exception logic.
- **`src/control_catalog.py`** — Defines control requirements, evidence sources, NIST CSF 2.0 mappings, risk assumptions, finding descriptions, and remediation recommendations.
- **`src/risk.py`** — Calculates likelihood × impact risk scores and classifies finding severity.
- **`src/reporting.py`** — Builds structured findings, executive metrics, remediation views, and report outputs.
- **`src/main.py`** — Orchestrates the end-to-end assessment workflow.
- **`tests/`** — Automated tests covering evidence validation, control logic, catalog metadata, risk calculations, and reporting behavior.

## Running the Project

### Requirements

- Python 3
- `pandas`
- `pytest`

Install the project dependencies:

```bash
python -m pip install -r requirements.txt
```

### Run the Assessment

From the project root:

```bash
python -m src.main
```

The assessment reads the sample evidence in `data/`, evaluates the seven controls, displays assessment results, and generates two persistent reporting artifacts:

```text
output/
├── control_findings.csv
└── management_report.md
```

### Run the Automated Tests

Run the complete test suite with:

```bash
python -m pytest -v
```

The project currently includes **74 automated tests** covering the assessment pipeline, including:

- evidence schema and value validation,
- control scope and assessability,
- control exceptions,
- evidence-quality issues,
- PASS, FAIL, and NOT ASSESSED behavior,
- control catalog metadata,
- NIST CSF mappings,
- risk scoring and severity,
- executive-summary calculations,
- management-report generation, and
- CSV and Markdown exports.

## Limitations & Future Development

Version 1 is intentionally scoped as a portfolio demonstration of automated cybersecurity control assurance rather than a production GRC platform or comprehensive security assessment.

### Current Limitations

- **Limited control set** — The engine evaluates seven controls across Identity and Access Management, Endpoint Security, and Third-Party Risk. It does not represent comprehensive coverage of Northstar BuildCo's cybersecurity program or the NIST CSF 2.0.

- **Static CSV evidence** — Evidence is supplied through local CSV files rather than collected directly from identity providers, endpoint-management platforms, security tools, or third-party systems.

- **Point-in-time assessment** — The engine evaluates the evidence supplied at execution time. It does not currently perform continuous control monitoring or retain assessment history.

- **Scenario-specific risk assumptions** — Likelihood and impact values are predefined for the fictional Northstar BuildCo scenario. A production implementation would require risk criteria calibrated to the organization's business context, risk appetite, threat environment, and governance methodology.

- **No remediation lifecycle tracking** — Findings include recommended remediation actions, but the engine does not currently assign owners, target dates, remediation status, management responses, or closure evidence.

- **No evidence provenance or attestation** — The engine validates the structure and supported values of submitted evidence but does not independently verify its source, authenticity, completeness, or collection method.

- **No automated framework coverage analysis** — NIST CSF 2.0 mappings are defined at the individual-control level. The project does not calculate overall framework maturity, compliance, or coverage.

- **No production security controls** — The application is a local assessment prototype and does not implement production capabilities such as authentication, authorization, encrypted evidence storage, audit logging, or multi-user access controls.

### Potential Future Development

Future versions could extend the architecture to support:

- additional control domains and control libraries,
- configurable control definitions and risk criteria,
- evidence ingestion through APIs or security-platform exports,
- historical assessment comparisons and control trending,
- remediation ownership and status tracking,
- evidence provenance and collection metadata,
- additional cybersecurity framework mappings,
- configurable reporting for different stakeholders,
- dashboards and visualization of control performance, and
- continuous or scheduled control monitoring.

These enhancements are intentionally outside the scope of version 1. The current project focuses on demonstrating a defensible control-assessment workflow, clear separation of evidence issues from confirmed exceptions, structured risk evaluation, and automated reporting.

## Skills Demonstrated

This project demonstrates the application of cybersecurity GRC concepts through software development and data-driven control testing, including:

- cybersecurity control design and assessment,
- evidence scoping and sufficiency analysis,
- identification of control exceptions and evidence-quality issues,
- Identity and Access Management (IAM) controls,
- endpoint security controls,
- third-party risk management,
- NIST CSF 2.0 control mapping,
- likelihood and impact risk assessment,
- executive and remediation-focused reporting,
- Python application development,
- structured data processing with pandas,
- modular software design,
- automated testing with pytest, and
- CSV and Markdown report generation.

The project is intended to demonstrate how cybersecurity governance and assurance concepts can be translated into repeatable, testable technical workflows.

## Disclaimer

**Northstar BuildCo is a fictional organization created solely for this project.** All users, devices, vendors, evidence records, control findings, risk assumptions, and assessment results are synthetic and do not represent a real organization or security assessment.

The project is provided for educational and portfolio purposes and should not be interpreted as a compliance certification, formal audit, or comprehensive implementation of the NIST Cybersecurity Framework.