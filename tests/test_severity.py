from pypanther.severity import PantherSeverity


def test_severity_less_than():
    assert PantherSeverity.info < PantherSeverity.low
    assert PantherSeverity.low < PantherSeverity.medium
    assert PantherSeverity.medium < PantherSeverity.high
    assert PantherSeverity.high < PantherSeverity.critical


def test_severity_as_int():
    assert PantherSeverity.as_int(PantherSeverity.info) == 0
    assert PantherSeverity.as_int(PantherSeverity.low) == 1
    assert PantherSeverity.as_int(PantherSeverity.medium) == 2
    assert PantherSeverity.as_int(PantherSeverity.high) == 3
    assert PantherSeverity.as_int(PantherSeverity.critical) == 4
