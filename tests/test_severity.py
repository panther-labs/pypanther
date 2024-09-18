import pytest

from pypanther.severity import Severity


def test_severity_less_than():
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL


def test_severity_as_int():
    assert Severity.as_int(Severity.INFO) == 0
    assert Severity.as_int(Severity.LOW) == 1
    assert Severity.as_int(Severity.MEDIUM) == 2
    assert Severity.as_int(Severity.HIGH) == 3
    assert Severity.as_int(Severity.CRITICAL) == 4

@pytest.mark.parametrize(("sev1", "sev2"), [
    ("CRITICAL", "HIGH"),
    ("HIGH", "MEDIUM"),
    ("MEDIUM", "LOW"),
    ("LOW", "INFO"),
    ("INFO", "INFO")
])
def test_severity_downgrading(sev1, sev2):
    assert Severity(sev1).downgrade() == Severity(sev2)

@pytest.mark.parametrize(("sev1", "sev2"), [
    ("CRITICAL", "CRITICAL"),
    ("HIGH", "CRITICAL"),
    ("MEDIUM", "HIGH"),
    ("LOW", "MEDIUM"),
    ("INFO", "LOW")
])
def test_severity_upgrading(sev1, sev2):
    assert Severity(sev1).upgrade() == Severity(sev2)