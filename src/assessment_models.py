# ============================================================
# CONTROL ASSURANCE ENGINE — ASSESSMENT DATA MODELS
# ============================================================

"""
Define structured data models for cybersecurity assessments.

These models represent assessment engagements, individual
control evaluations, and documented security findings.
"""

from dataclasses import dataclass
from datetime import date
from src.risk import calculate_risk_score, classify_risk


@dataclass (frozen=True)
class Assessment:
    """
    Represent a cybersecurity assessment engagement.

    Attributes:
        assessment_id:
            Unique identifier for the assessment.

        organization:
            Name of the organization being assessed.

        assessor:
            Name of the person conducting the assessment.

        assessment_date:
            Date the assessment was initiated.

        framework:
            Cybersecurity framework used for the assessment.

        scope:
            Description of the systems, processes, or
            organizational areas included in the assessment.
    """

    assessment_id: str
    organization: str
    assessor: str
    assessment_date: date
    framework: str
    scope: str

    def __post_init__(self):
        '''
        Validate assessment information after initialization.

        Reject missing or blank text fields and assessment
        dates that are not datetime.date objects.
        '''

        # Validate all required text fields.
        required_fields = (
            'assessment_id',
            'organization',
            'assessor',
            'framework',
            'scope'
        )

        for field_name in required_fields:
            value = getattr(self, field_name)

            # Reject non-string values and whitespace-only strings.
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"'{field_name}' must be a non-empty string.")

        # Require a date-only object, excluding datetime timestamps.
        if type(self.assessment_date) is not date:
            raise ValueError(
                'assessment_date must be a datetime.date object.'
            )


@dataclass (frozen=True)
class ControlAssessment:
    '''
    Represent the evaluation of one security control
    within a cybersecurity assessment.

    Attributes:
        assessment_id:
            Identifier of the parent assessment.

        control_id:
            Identifier of the evaluated security control.

        assessment_method:
            Method used to evaluate the control:
            AUTOMATED, MANUAL, or HYBRID.

        implementation_status:
            Control implementation status:
            IMPLEMENTED, PARTIALLY_IMPLEMENTED, NOT_IMPLEMENTED,
            NOT_ASSESSED, or NOT_APPLICABLE.

        evidence_status:
            Sufficiency of evidence supporting the assessment:
            NOT_REVIEWED, SUFFICIENT, or INSUFFICIENT.

        evidence_references:
            References to the evidence supporting the assessment.

        observations:
            Documented assessor observations.
        '''

    assessment_id: str
    control_id: str
    assessment_method: str
    implementation_status: str
    evidence_status: str
    evidence_references: list[str]
    observations: str

    def __post_init__(self):
        '''
        Validate control assessment attributes after initialization.
        '''

        # Validate the identifiers linking this record
        # to its parent assessment and security control.
        required_identifiers = (
            'assessment_id',
            'control_id'
        )

        for field_name in required_identifiers:
            value = getattr(self, field_name)

            # Reject missing, non-string, or blank identifiers.
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"'{field_name}' must be a non-empty string."
                )

        # Define the supported methods of control evaluation.
        valid_methods = {
            'AUTOMATED',
            'MANUAL',
            'HYBRID'
        }

        # Reject unsupported methods and non-string values.
        if (
            not isinstance(self.assessment_method, str)
            or self.assessment_method not in valid_methods
        ):
            raise ValueError(
                'assessment_method must be one of: '
                'AUTOMATED, MANUAL, or HYBRID.'
            )

        # Define the supported control implementation statuses.
        valid_statuses = {
            'IMPLEMENTED',
            'PARTIALLY_IMPLEMENTED',
            'NOT_IMPLEMENTED',
            'NOT_ASSESSED',
            'NOT_APPLICABLE'
        }

        # Reject unsupported implementation statuses.
        if (
            not isinstance(self.implementation_status, str)
            or self.implementation_status not in valid_statuses
        ):
            raise ValueError(
                'implementation_status must be one of: '
                'IMPLEMENTED, PARTIALLY_IMPLEMENTED, NOT_IMPLEMENTED, '
                'NOT_ASSESSED, NOT_APPLICABLE.'
            )

        # Evidence reference must be provided as a list.
        if not isinstance(self.evidence_references, list):
            raise ValueError('evidence_references must be a list of strings.')

        # Validate each reference within the list.
        for reference in self.evidence_references:

            # Reject non-string and whitespace-only references.
            if not isinstance(reference, str) or not reference.strip():
                raise ValueError('Each evidence reference must be a non-empty string.')

        # Convert validated references into an immutable tuple.
        # object.__setattr__ permits initialization within
        # a frozen dataclass without allowing later reassignment.
        object.__setattr__(
            self,
            'evidence_references',
            tuple(self.evidence_references),
        )

        # Observations must be stored as a text.
        # Empty observations are permitted for assesement in progress.
        if not isinstance(self.observations, str):
            raise ValueError(
                'observations must be a string. '
                'Use an empty string if no observations are available.'
            )

        # Define the supported evidence sufficiency statuses.
        valid_evidence_statuses = {
            'NOT_REVIEWED',
            'SUFFICIENT',
            'INSUFFICIENT'
        }

        # Reject unsupported evidence statuses and data types.
        if (
            not isinstance(self.evidence_status, str)
            or self.evidence_status not in valid_evidence_statuses
        ):
            raise ValueError(
                'evidence_status must be one of: '
                'NOT_REVIEWED, SUFFICIENT, INSUFFICIENT.'
            )


@dataclass(frozen=True)
class Finding:

    '''
    Represent a security finding identified during
    a cybersecurity control assessment.

    Multiple findings may be associated with the same
    control within an assessment.

    Attributes:
        finding_id:
            Unique identifier for the finding.

        assessment_id:
            Identifier of the parent assessment.

        control_id:
            Identifier of the affected security control.

        description:
            Description of the identified security issue.

        likelihood:
            Estimated likelihood of the associated risk,
            using a scale from 1 to 5.

        impact:
            Estimated impact of the associated risk,
            using a scale from 1 to 5.

        risk_rationale:
            Explanation supporting the risk assessment.

        recommendation:
            Recommended action to address the finding.

    Properties:
        risk_score:
            Calculated likelihood multiplied by impact.

        risk_severity:
            Risk classification derived from the
            calculated risk score.
    '''


    finding_id: str
    assessment_id: str
    control_id: str
    description: str
    likelihood: int
    impact: int
    risk_rationale: str
    recommendation: str

    def __post_init__(self):
        '''
        Validate finding attributes after initialization.

        Reject missing, blank, or incorrectly typed
        identifiers and required text fields.
        '''

        # Define the required identifiers and descriptive fields.
        required_fields = (
            'finding_id',
            'assessment_id',
            'control_id',
            'description',
            'risk_rationale',
            'recommendation'
        )

        # Validate each required field.
        for field_name in required_fields:
            value = getattr(self, field_name)

            # Reject non-string values and whitespace-only strings.
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f'{field_name} must be a non-empty string.'
                )

        # Validate risk assessment inputs.
        for field_name in ('likelihood', 'impact'):
            value = getattr(self, field_name)

            # Require an integer from 1 to 5.
            # type(value) is int explicitly excludes Boolean values,
            # since bool is a subclass of int in Python.
            if type(value) is not int or not 1 <= value <= 5:
                raise ValueError(
                    f'{field_name} must be an integer between 1 and 5'
                )


    @property
    def risk_score(self) -> int:
        '''
        Calculate the finding's risk score using
        the existing risk-scoring engine.

        Risk score = likelihood x impact.
        '''

        return calculate_risk_score(
            self.likelihood,
            self.impact,
        )


    @property
    def risk_severity(self) -> str:
        '''
        Classify the finding's calculated risk score
        using the existing risk classification engine.
        '''

        return classify_risk(self.risk_score)
