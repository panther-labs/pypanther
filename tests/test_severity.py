from pypanther.severity import Severity


def test_severity_less_than():
    assert Severity.info < Severity.low
    assert Severity.low < Severity.medium
    assert Severity.medium < Severity.high
    assert Severity.high < Severity.critical


def test_severity_as_int():
    assert Severity.as_int(Severity.info) == 0
    assert Severity.as_int(Severity.low) == 1
    assert Severity.as_int(Severity.medium) == 2
    assert Severity.as_int(Severity.high) == 3
    assert Severity.as_int(Severity.critical) == 4
