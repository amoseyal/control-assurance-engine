"""Tests for risk score calculation and severity classification."""

import pytest

from src.risk import calculate_risk_score, classify_risk


def test_calculate_risk_score():
    """Verify that the risk score is likelihood multiplied by impact."""
    risk_score = calculate_risk_score(likelihood=4, impact=5)

    assert risk_score == 20


def test_classify_risk():
    """Verify that risk scores map to the appropriate severity levels."""
    # LOW covers scores 1 through 4.
    assert classify_risk(1) == "LOW"
    assert classify_risk(4) == "LOW"

    # MODERATE covers scores 5 through 9.
    assert classify_risk(5) == "MODERATE"
    assert classify_risk(9) == "MODERATE"

    # HIGH covers scores 10 through 16.
    assert classify_risk(10) == "HIGH"
    assert classify_risk(16) == "HIGH"

    # CRITICAL covers scores 17 through 25.
    assert classify_risk(17) == "CRITICAL"
    assert classify_risk(25) == "CRITICAL"


def test_calculate_risk_score_rejects_invalid_ratings():
    """Verify that ratings outside the 1-to-5 scale are rejected."""
    with pytest.raises(ValueError):
        calculate_risk_score(likelihood=0, impact=3)

    with pytest.raises(ValueError):
        calculate_risk_score(likelihood=6, impact=3)

    with pytest.raises(ValueError):
        calculate_risk_score(likelihood=3, impact=0)

    with pytest.raises(ValueError):
        calculate_risk_score(likelihood=3, impact=6)


def test_calculate_risk_score_rejects_non_integer_ratings():
    """Verify that likelihood and impact ratings must be integers."""
    with pytest.raises(TypeError):
        calculate_risk_score(likelihood=2.5, impact=3)

    with pytest.raises(TypeError):
        calculate_risk_score(likelihood=3, impact=4.5)


def test_calculate_risk_score_rejects_boolean_ratings():
    """Verify that Boolean ratings are rejected despite bool subclassing int."""
    with pytest.raises(TypeError):
        calculate_risk_score(likelihood=True, impact=3)

    with pytest.raises(TypeError):
        calculate_risk_score(likelihood=3, impact=False)
