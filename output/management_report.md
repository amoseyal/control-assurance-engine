# Northstar BuildCo

## Cybersecurity Control Assurance Assessment

## Executive Summary

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

## Findings Requiring Remediation

### IAM-01 | HIGH

**Finding:** Active user accounts were identified without MFA enabled, increasing the risk of unauthorized access if credentials are compromised.

**Affected:** mlopez, jparis, snguyen

**Recommendation:** Enable MFA for all active user accounts and verify enrollment.

### IAM-02 | HIGH

**Finding:** Terminated user accounts were identified as still enabled, increasing the risk of unauthorized access after employment ends.

**Affected:** malvarez

**Recommendation:** Disable terminated user accounts promptly and verify account deactivation as part of the offboarding process.

### IAM-03 | HIGH

**Finding:** Administrative privileges were identified on accounts without documented approval, increasing the risk of unauthorized privileged access.

**Affected:** akim

**Recommendation:** Remove unapproved administrative privileges or document appropriate authorization, and periodically review privileged account access.

### END-01 | HIGH

**Finding:** Company-managed endpoints were identified without disk encryption, increasing the risk of unauthorized access to data if a device is lost, stolen, or otherwise physically compromised.

**Affected:** DEV-002, DEV-005

**Recommendation:** Enable full-disk encryption on all company-managed endpoints and periodically verify encryption status through endpoint management.

### TPR-01 | HIGH

**Finding:** Critical third-party vendors were identified without a documented security review, limiting the organization's ability to understand and manage cybersecurity risks introduced by those vendors.

**Affected:** VND-003

**Recommendation:** Complete and document security reviews for all critical third-party vendors and establish a process for periodic reassessment.

### TPR-02 | HIGH

**Finding:** Third-party vendors with privileged access were identified without MFA enabled, increasing the risk that compromised vendor credentials could be used to gain unauthorized privileged access.

**Affected:** VND-002

**Recommendation:** Require MFA for all third-party vendors with privileged access and periodically verify that MFA remains enforced.