from pypanther import register
from pypanther.base import PantherRule, PantherSeverity
from pypanther.registry import registered_rules


def test_register_duplicate():
    class A(PantherRule):
        tags = ["test"]
        log_types = [""]
        id_ = "test_register_duplicate"
        default_severity = PantherSeverity.info

        def rule(self, _):
            pass

    register(A)
    A.default_tags.append("test2")
    register(A)
    assert len(registered_rules()) == 1
