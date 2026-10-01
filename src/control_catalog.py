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
        'impact': 4
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
            'impact': 5
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
        'impact': 5
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
        'impact': 4
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
        'impact': 4
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
        'impact': 4
    }
}