# ------------------------------------------------------------------
# Risk-scoring functions for the Control Assurance Engine.
# ------------------------------------------------------------------

"""
This module contains logic for calculating and classifying
risk associated with control-assessment findings.
"""


def calculate_risk_score(likelihood, impact):
    """
    Calculate a risk score from likelihood and impact.

    Parameters:
        likelihood:
            Integer rating from 1 through 5 representing the
            likelihood that the risk event could occur.

        impact:
            Integer rating from 1 through 5 representing the
            potential impact if the risk event occurs.

    Returns:
        The calculated risk score.

    Raises:
        ValueError:
            If likelihood or impact is not an integer or is
            outside the permitted 1-to-5 rating scale.
    """

    # Verify that likelihood uses a whole-number rating.
    #
    # Boolean values must be rejected explicitly because Python
    # treats bool as a subclass of int. Without this check,
    # True could incorrectly be accepted as the numeric value 1.
    if isinstance(likelihood, bool) or not isinstance(likelihood, int):
        raise ValueError(
            'Likelihood must be an integer between 1 and 5.'
        )

    # Apply the same type validation to the impact rating.
    #
    # This prevents values such as 2.5, '4', True, or None
    # from being treated as valid risk ratings.
    if isinstance(impact, bool) or not isinstance(impact, int):
        raise ValueError(
            'Impact must be an integer between 1 and 5.'
        )

    # Validate that likelihood is within the permitted
    # 1-to-5 risk-rating scale.
    if likelihood < 1 or likelihood > 5:
        raise ValueError(
            'Likelihood must be between 1 and 5.'
        )

    # Validate that impact is within the permitted
    # 1-to-5 risk-rating scale.
    if impact < 1 or impact > 5:
        raise ValueError(
            'Impact must be between 1 and 5.'
        )

    # Calculate risk only after both ratings have
    # passed type and range validation.
    risk_score = likelihood * impact

    return risk_score


def classify_risk(risk_score):
    """
    Classify a numeric risk score into a qualitative
    severity level.

    Parameters:
        risk_score:
            Numeric risk score produced by multiplying
            likelihood by impact.

    Returns:
        A qualitative risk severity classification.

    Risk classification:
        1-4:
            LOW

        5-9:
            MODERATE

        10-16:
            HIGH

        17-25:
            CRITICAL
    """

    # Classify the risk score according to the
    # Control Assurance Engine's risk matrix.
    if risk_score <= 4:
        return 'LOW'
    elif risk_score <= 9:
        return 'MODERATE'
    elif risk_score <= 16:
        return 'HIGH'
    else:
        return 'CRITICAL'