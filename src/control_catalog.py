# ============================================================
# CONTROL CATALOG
# ============================================================

# Define the authoritative metadata for security controls
# evaluated by the Control Assurance Engine.
#
# Each control is stored under its unique control ID so that
# assessment and reporting components can retrieve consistent
# metadata without redefining it elsewhere.
CONTROL_CATALOG = {
    'IAM-01': {
        'control_id': 'IAM-01',
        'domain': 'Identity and Access Management',
        'requirement': (
            'All active user accounts must have MFA enabled.'
        ),
        'evidence_source': 'users.csv',
        'entity_label': 'Accounts',

        # Map the control to the relevant NBIST CSF 2.0 coutcome.
        'nist_csf_function': 'Protect',
        'nist_csf_category': 'PR.AA',
        'nist_csf_category_name': (
            'Identity Management, Authentication, and Access Control'
        ),
        'nist_csf_subcategory': 'PR.AA-03',
        'nist_csf_subcategory_outcome': (
            'Users, services, and hardware are authenticated'
        ),

        # Define the baseline risk associated with failure
        # of this control in the Northstar BuildCo scenario.
        'likelihood': 4,
        'impact': 4,

        # Management-readable explanation of the condition and
        # the security risk created when the control fails.
        'finding_description': (
            'Active user accounts were identified without MFA enabled, '
            'increasing the risk of unauthorized access if credentials '
            'are compromised.'
        ),

        # Recommended management action for remediating the
        # control deficiency.
        'recommendation': (
            'Enable MFA for all active user accounts and verify enrollment.'
        ),
    },

    'IAM-02': {
            'control_id': 'IAM-02',
            'domain': 'Identity and Access Management',
            'requirement': (
                'Terminated users must have their accounts disabled.'
            ),
            'evidence_source': 'users.csv',
            'entity_label': 'Accounts',

            # Map the control to the relevant NIST CSF 2.0 outcome.
            'nist_csf_function': 'Protect',
            'nist_csf_category': 'PR.AA',
            'nist_csf_category_name': (
                'Identity Management, Authentication, and Access Control'
            ),
            'nist_csf_subcategory': 'PR.AA-05',
            'nist_csf_subcategory_outcome': (
                'Access permissions, entitlements, and authorizations are '
                'defined in a policy, managed, enforced, and reviewed, and '
                'incorporate the principles of least privilege and '
                'separation of duties'
            ),

            # Definre the baseline risk associated with failure
            # of this control in the Northstar BuildCo scenario.
            'likelihood': 3,
            'impact': 5,

            # Management-readable explanation of the condition and
            # the security risk created when the control fails.
            'finding_description': (
            'Terminated user accounts were identified as still enabled, '
            'increasing the risk of unauthorized access after employment ends.'
            ),

            # Recommended management action for remediating the
            # control deficiency.
            'recommendation': (
            'Disable terminated user accounts promptly and verify account '
            'deactivation as part of the offboarding process.'
            ),
    },

    'IAM-03': {
        'control_id': 'IAM-03',
        'domain': 'Identity and Access Management',
        'requirement': (
            'Administrative privileges must be limited to approved accounts.'
        ),
        'evidence_source': 'users.csv',
        'entity_label': 'Accounts',

        # Map the control to the relevant NIST CSF 2.0 outcome.
        'nist_csf_function': 'Protect',
        'nist_csf_category': 'PR.AA',
        'nist_csf_category_name': (
            'Identity Management, Authentication, and Access Control'
        ),
        'nist_csf_subcategory': 'PR.AA-05',
        'nist_csf_subcategory_outcome': (
            'Access permissions, entitlements, and authorizations are '
            'defined in a policy, managed, enforced, and reviewed, and '
            'incorporate the principles of least privilege and '
            'separation of duties'
        ),

        # Define the baseline risk associated with failure
        # of this control in the Northstar BuildCo scenario.
        'likelihood': 3,
        'impact': 5,

        # Management-readable explanation of the condition and
        # the security risk created when the control fails.
        'finding_description': (
            'Administrative privileges were identified on accounts without '
            'documented approval, increasing the risk of unauthorized '
            'privileged access.'
        ),

        # Recommended management action for remediating the
        # control deficiency.
        'recommendation': (
            'Remove unapproved administrative privileges or document appropriate '
            'authorization, and periodically review privileged account access.'
        ),
    },

    'END-01': {
        'control_id': 'END-01',
        'domain': 'Endpoint Security',
        'requirement': (
            'Company-managed endpoints must use disk encryption.'
        ),
        'evidence_source': 'devices.csv',
        'entity_label': 'Devices',

                # Map the control to the relevant NIST CSF 2.0 outcome.
        'nist_csf_function': 'Protect',
        'nist_csf_category': 'PR.DS',
        'nist_csf_category_name': 'Data Security',
        'nist_csf_subcategory': 'PR.DS-01',
        'nist_csf_subcategory_outcome': (
            'The confidentiality, integrity, and availability '
            'of data-at-rest are protected'
        ),

        # Definre the baseline risk associated with failure
        # of this control in the Northstar BuildCo scenario.
        'likelihood': 3,
        'impact': 4,

        # Management-readable explanation of the condition and
        # the security risk created when the control fails.
        'finding_description': (
            'Company-managed endpoints were identified without disk encryption, '
            'increasing the risk of unauthorized access to data if a device '
            'is lost, stolen, or otherwise physically compromised.'
        ),

        # Recommended management action for remediating the
        # control deficiency.
        'recommendation': (
            'Enable full-disk encryption on all company-managed endpoints and '
            'periodically verify encryption status through endpoint management.'
        ),
    },

    'END-02': {
        'control_id': 'END-02',
        'domain': 'Endpoint Security',
        'requirement': (
            'Company-managed endpoints must have endpoint protection enabled.'
        ),
        'evidence_source': 'devices.csv',
        'entity_label': 'Devices',

        # Map the control to the relevant NIST CSF 2.0 outcome.
        'nist_csf_function': 'Protect',
        'nist_csf_category': 'PR.PS',
        'nist_csf_category_name': 'Platform Security',
        'nist_csf_subcategory': 'PR.PS-05',
        'nist_csf_subcategory_outcome': (
            'Installation and execution of unauthorized '
            'software are prevented'
        ),

        # Definre the baseline risk associated with failure
        # of this control in the Northstar BuildCo scenario.
        'likelihood': 4,
        'impact': 4,

        # Management-readable explanation of the condition and
        # the security risk created when the control fails.
        'finding_description': (
            'Company-managed endpoints were identified without endpoint '
            'protection enabled, increasing exposure to malware and other '
            'endpoint-based threats.'
        ),

        # Recommended management action for remediating the
        # control deficiency.
        'recommendation': (
            'Enable and centrally manage endpoint protection on all '
            'company-managed endpoints and periodically verify protection status.'
        ),
    },

    'TPR-01': {
        # Unique identifier used throughout the assessment engine.
        'control_id': 'TPR-01',

        # Control domain used to group related controls.
        'domain': 'Third-Party Risk',

        # Plain-language statement describing the control
        # requirement being assessed.
        'requirement': (
            'Critical third-party vendors must have a documented '
            'security review.'
        ),

        # Evidence file used to evaluate this control.
        'evidence_source': 'vendors.csv',

        # Human-readable label used when reporting affected
        # entities for this control.
        'entity_label': 'Vendors',

        # NIST Cybersecurity Framework 2.0 mapping.
        #
        # GV.SC addresses Cybersecurity Supply Chain Risk
        # Management. GV.SC-07 covers assessing and monitoring
        # risks posed by suppliers and other third parties
        # throughout the relationship.
        'nist_csf_function': 'Govern',
        'nist_csf_category': 'GV.SC',
        'nist_csf_category_name': (
            'Cybersecurity Supply Chain Risk Management'
        ),
        'nist_csf_subcategory': 'GV.SC-07',
        'nist_csf_subcategory_outcome': (
            'The risks posed by a supplier, their products and services, '
            'and other third parties are understood, recorded, prioritized, '
            'assessed, responded to, and monitored over the course of the '
            'relationship'
        ),

        # Define Northstar BuildCo's baseline risk assumptions
        # for a failed TPR-01 control assessment.
        #
        # These ratings are scenario-specific and are not
        # prescribed by NIST CSF 2.0.
        'likelihood': 3,
        'impact': 4,

        # Management-readable explanation of the condition and
        # the security risk created when the control fails.
        'finding_description': (
            'Critical third-party vendors were identified without a documented '
            'security review, limiting the organization\'s ability to understand '
            'and manage cybersecurity risks introduced by those vendors.'
        ),

        # Recommended management action for remediating the
        # control deficiency.
        'recommendation': (
            'Complete and document security reviews for all critical third-party '
            'vendors and establish a process for periodic reassessment.'
        ),
    },

    'TPR-02': {
    # Unique identifier used throughout the assessment engine.
    'control_id': 'TPR-02',

    # Control domain used to group related security requirements.
    'domain': 'Third-Party Risk',

    # Northstar's internal control requirement.
    'requirement': (
        'Third-party vendors with privileged access must use MFA.'
    ),

    # Evidence source used to evaluate this control.
    'evidence_source': 'vendors.csv',

    # Human-readable label used when reporting affected entities.
    'entity_label': 'Vendors',

    # NIST Cybersecurity Framework 2.0 mapping.
    #
    # Although TPR-02 operates within Northstar's third-party
    # risk domain, its underlying security objective is
    # authentication of privileged access.
    'nist_csf_function': 'Protect',
    'nist_csf_category': 'PR.AA',
    'nist_csf_category_name': (
        'Identity Management, Authentication, and Access Control'
    ),
    'nist_csf_subcategory': 'PR.AA-03',
    'nist_csf_subcategory_outcome': (
        'Users, services, and hardware are authenticated'
    ),

    # Baseline risk assumptions for Northstar.
    #
    # Likelihood and impact represent the inherent significance
    # of a confirmed TPR-02 failure. Active finding severity is
    # assigned later only when the control actually fails.
    'likelihood': 3,
    'impact': 5,

    # Management-readable explanation of the condition and
    # the security risk created when the control fails.
    'finding_description': (
        'Third-party vendors with privileged access were identified without '
        'MFA enabled, increasing the risk that compromised vendor credentials '
        'could be used to gain unauthorized privileged access.'
    ),

    # Recommended management action for remediating the
    # control deficiency.
    'recommendation': (
        'Require MFA for all third-party vendors with privileged access and '
        'periodically verify that MFA remains enforced.'
    ),
    }
}