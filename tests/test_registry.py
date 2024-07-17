from pypanther import register
from pypanther.base import Rule, Severity
from pypanther.data_models_v2 import DataModel
from pypanther.registry import registered_data_models, registered_rules


def test_register_rule_duplicate():
    class A(Rule):
        tags = ["test"]
        log_types = [""]
        id = "test_register_duplicate"
        default_severity = Severity.INFO

        def rule(self, _):
            pass

    register(A)
    A.tags.append("test2")
    register(A)
    assert len(registered_rules()) == 1


def test_register_rules():
    class A(Rule):
        log_types = [""]
        id = "a"
        default_severity = Severity.INFO

        def rule(self, _):
            pass

    class B(Rule):
        log_types = [""]
        id = "b"
        default_severity = Severity.INFO

        def rule(self, _):
            pass

    register([A, B])
    assert len(registered_rules()) == 2
    assert A in registered_rules()
    assert B in registered_rules()


def test_register_data_model_duplicate():
    class A(DataModel):
        data_model_id = "test_register_duplicate"

    register(A)
    register(A)
    assert len(registered_data_models()) == 1


def test_register_data_models():
    class A(DataModel):
        id = "a"

    class B(DataModel):
        id = "b"

    register([A, B])
    assert len(registered_data_models()) == 2
    assert A in registered_data_models()
    assert B in registered_data_models()


def test_invalid_argument():
    register("hello")


def test_invalid_argument_in_iterable():
    register(["hello"])
