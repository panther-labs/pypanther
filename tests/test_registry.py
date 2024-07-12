from pypanther import register
from pypanther.base import Rule, Severity
from pypanther.registry import registered_rules


def test_register_duplicate():
    class A(Rule):
        tags = ["test"]
        log_types = [""]
        id_ = "test_register_duplicate"
        default_severity = Severity.info

        def rule(self, _):
            pass

    register(A)
    A.tags.append("test2")
    register(A)
    assert len(registered_rules()) == 1
