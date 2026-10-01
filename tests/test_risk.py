# ------------------------------------------------------------------
# Tests for the control assurance engine's risk-scoring logic.
# ------------------------------------------------------------------

import pytest

from src.risk import calculate_risk_score, classify_risk


def test_calculate_risk_score():
    """
    Verify that the risk score is calculated by multiplying
    likelihood by impact.
    """

    # A likelihood of 4 and an impact of 5 should produce
    # a risk score of 20.
    risk_score = calculate_risk_score(
        likelihood=4,
        impact=5
    )

    assert risk_score == 20


def test_classify_risk():
    """
    Verify that risk scores are classified into the
    appropriate qualitative severity levels.
    """

    # Scores from 1 through 4 should be LOW.
    assert classify_risk(1) == 'LOW'
    assert classify_risk(4) == 'LOW'

    # Scores from 5 through 9 should be MODERATE.
    assert classify_risk(5) == 'MODERATE'
    assert classify_risk(9) == 'MODERATE'

    # Scores from 10 through 16 should be HIGH.
    assert classify_risk(10) == 'HIGH'
    assert classify_risk(16) == 'HIGH'

    # Scores from 17 through 25 should be CRITICAL.
    assert classify_risk(17) == 'CRITICAL'
    assert classify_risk(25) == 'CRITICAL'


def test_calculate_risk_score_rejects_invalid_ratings():
    """
    Verify that likelihood and impact ratings outside
    the 1-to-5 scale are rejected.
    """

    # Likelihood cannot be below the minimum rating of 1.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=0,
            impact=3
        )

    # Likelihood cannot exceed the maximum rating of 5.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=6,
            impact=3
        )

    # Impact cannot be below the minimum rating of 1.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=3,
            impact=0
        )

    # Impact cannot exceed the maximum rating of 5.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=3,
            impact=6
        )


def test_calculate_risk_score_rejects_non_integer_ratings():
    """
    Verify that likelihood and impact must be integer
    ratings on the 1-to-5 scale.
    """

    # A fractional likelihood is not a valid rating.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=2.5,
            impact=3
        )

    # A fractional impact is not a valid rating.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=3,
            impact=4.5
        )


def test_calculate_risk_score_rejects_boolean_ratings():
    """
    Verify that Boolean values are rejected even though
    Python treats bool as a subclass of int.
    """

    # True would otherwise behave numerically like 1.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=True,
            impact=3
        )

    # False would otherwise behave numerically like 0.
    with pytest.raises(ValueError):
        calculate_risk_score(
            likelihood=3,
            impact=False
        )