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
        'entity_label': 'Accounts'
    },

    'IAM-02': {
            'control_id': 'IAM-02',
            'domain': 'Identity and Access Management',
            'requirement': (
                'Terminated users must have their accounts disabled.'
            ),
            'evidence_source': 'users.csv',
            'entity_label': 'Accounts'
        },

    'IAM-03': {
        'control_id': 'IAM-03',
        'domain': 'Identity and Access Management',
        'requirement': (
            'Administrative privileges must be limited to approved accounts.'
        ),
        'evidence_source': 'users.csv',
        'entity_label': 'Accounts'
    },

    'END-01': {
        'control_id': 'END-01',
        'domain': 'Endpoint Security',
        'requirement': (
            'Company-managed endpoints must use disk encryption.'
        ),
        'evidence_source': 'devices.csv',
        'entity_label': 'Devices'
    },

    'END-02': {
        'control_id': 'END-02',
        'domain': 'Endpoint Security',
        'requirement': (
            'Company-managed endpoints must have endpoint protection enabled.'
        ),
        'evidence_source': 'devices.csv',
        'entity_label': 'Devices'
    }
}