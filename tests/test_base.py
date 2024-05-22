from panther_analysis.base import PantherRule, Severity


def test_less_than():
    assert Severity.Info < Severity.Low
    assert Severity.Low < Severity.Medium
    assert Severity.Medium < Severity.High
    assert Severity.High < Severity.Critical


def test_as_int():
    assert Severity.as_int(Severity.Info) == 0
    assert Severity.as_int(Severity.Low) == 1
    assert Severity.as_int(Severity.Medium) == 2
    assert Severity.as_int(Severity.High) == 3
    assert Severity.as_int(Severity.Critical) == 4


def test_inheritance():
    class Test(PantherRule):
        Tags = ["test"]

        def rule(self, event):
            pass

    class Test2(Test):
        def rule(self, event):
            pass

    # values are inherited as copies
    assert Test2.Tags == ["test"]
    assert Test.Tags == ["test"]
    assert Test.Tags is not Test2.Tags

    # updates do not affect the parent or children
    Test2.Tags.append("test2")
    assert Test2.Tags == ["test", "test2"]
    assert Test.Tags == ["test"]
    Test.Tags.append("test3")
    assert Test2.Tags == ["test", "test2"]
    assert Test.Tags == ["test", "test3"]
