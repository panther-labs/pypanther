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
