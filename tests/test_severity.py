from pypanther.severity import PantherSeverity


def test_severity_less_than():
    assert PantherSeverity.Info < PantherSeverity.Low
    assert PantherSeverity.Low < PantherSeverity.Medium
    assert PantherSeverity.Medium < PantherSeverity.High
    assert PantherSeverity.High < PantherSeverity.Critical


def test_severity_as_int():
    assert PantherSeverity.as_int(PantherSeverity.Info) == 0
    assert PantherSeverity.as_int(PantherSeverity.Low) == 1
    assert PantherSeverity.as_int(PantherSeverity.Medium) == 2
    assert PantherSeverity.as_int(PantherSeverity.High) == 3
    assert PantherSeverity.as_int(PantherSeverity.Critical) == 4
