from pypanther import register
from pypanther.base import PantherRule, PantherSeverity
from pypanther.register import registered_rules


def test_register_duplicate():
    class A(PantherRule):
        Tags = ["test"]
        LogTypes = [""]
        RuleID = "test_register_duplicate"
        Severity = PantherSeverity.Info

        def rule(self, _):
            pass

    register(A)
    A.Tags.append("test2")
    register(A)
    assert len(registered_rules()) == 1
