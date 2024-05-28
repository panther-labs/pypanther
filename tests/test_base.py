from pypanther.base import PANTHER_RULE_ALL_ATTRS, PantherRule, PantherRuleModel, PantherSeverity
from pypanther.log_types import LogType


def test_less_than():
    assert PantherSeverity.Info < PantherSeverity.Low
    assert PantherSeverity.Low < PantherSeverity.Medium
    assert PantherSeverity.Medium < PantherSeverity.High
    assert PantherSeverity.High < PantherSeverity.Critical


def test_as_int():
    assert PantherSeverity.as_int(PantherSeverity.Info) == 0
    assert PantherSeverity.as_int(PantherSeverity.Low) == 1
    assert PantherSeverity.as_int(PantherSeverity.Medium) == 2
    assert PantherSeverity.as_int(PantherSeverity.High) == 3
    assert PantherSeverity.as_int(PantherSeverity.Critical) == 4


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


def test_override():
    class Test(PantherRule):
        RuleID = "old"
        Severity = PantherSeverity.High
        LogTypes = [LogType.Panther_Audit, LogType.AlphaSOC_Alert]
        Tags = ["old", "old2"]

    assert Test.RuleID == "old"
    assert Test.Severity == PantherSeverity.High
    assert Test.LogTypes == [LogType.Panther_Audit, LogType.AlphaSOC_Alert]
    assert Test.Tags == ["old", "old2"]

    Test.override(
        RuleID="new",
        Severity=PantherSeverity.Low,
        LogTypes=[LogType.Amazon_EKS_Audit],
        Tags=Test.Tags + ["new"],
    )

    assert Test.RuleID == "new"
    assert Test.Severity == PantherSeverity.Low
    assert Test.LogTypes == [LogType.Amazon_EKS_Audit]
    assert Test.Tags == ["old", "old2", "new"]


def test_panther_rule_fields_match():
    assert (
        set(PANTHER_RULE_ALL_ATTRS)
        == set(PantherRuleModel.__annotations__)
        == set(PantherRule.__annotations__)
        == set(PantherRule.override.__annotations__)
    )
