import unittest

import pytest

from pypanther import LogType, register
from pypanther.base import Rule, Severity
from pypanther.data_models_v2 import DataModel
from pypanther.registry import (
    _DATA_MODEL_REGISTRY,
    _RULE_ID_TO_RULE_REGISTRY,
    _RULE_REGISTRY,
    registered_data_models,
    registered_rules,
)


class RuleA(Rule):
    log_types = [LogType.OKTA_SYSTEM_LOG]
    id = "rule_a"
    create_alert = True
    dedup_period_minutes = 60
    display_name = "Rule A"
    enabled = True
    summary_attributes = ["foo"]
    threshold = 1
    tags = ["tag A"]
    default_severity = Severity.INFO
    default_description = "description A"
    default_reference = "reference A"
    default_runbook = "runbook A"
    default_destinations = ["destination A"]

    def rule(self, _):
        pass


class RuleB(Rule):
    log_types = [LogType.AWS_CLOUDTRAIL]
    id = "rule_b"
    create_alert = False
    dedup_period_minutes = 120
    display_name = "Rule B"
    enabled = False
    summary_attributes = ["bar"]
    threshold = 10
    tags = ["tag B"]
    default_severity = Severity.LOW
    default_description = "description B"
    default_reference = "reference B"
    default_runbook = "runbook B"
    default_destinations = ["destination B"]

    def rule(self, _):
        pass


class TestRegister(unittest.TestCase):
    def setUp(self):
        _RULE_REGISTRY.clear()
        _RULE_ID_TO_RULE_REGISTRY.clear()
        _DATA_MODEL_REGISTRY.clear()

    def test_register_rule_duplicate(self):
        register(RuleA)
        RuleA.tags.append("test2")
        register(RuleA)
        assert len(registered_rules()) == 1
        assert RuleA in registered_rules()

    def test_register_rule_duplicate_id(self):
        class RuleA(Rule):
            log_types = [LogType.OKTA_SYSTEM_LOG]
            id = "rule_1"
            default_severity = Severity.INFO

            def rule(self, _):
                pass

        class RuleB(Rule):
            log_types = [LogType.OKTA_SYSTEM_LOG]
            id = "rule_1"
            default_severity = Severity.INFO

            def rule(self, _):
                pass

        with pytest.raises(ValueError, match="Rule with id 'rule_1' is already registered"):
            register(RuleA)
            register(RuleB)

    def test_register_rule_duplicate_in_list(self):
        register([RuleA, RuleA])
        assert len(registered_rules()) == 1
        assert RuleA in registered_rules()

    def test_register_rules(self):
        register([RuleA, RuleB])
        assert len(registered_rules()) == 2
        assert RuleA in registered_rules()
        assert RuleB in registered_rules()

    def test_register_data_model_duplicate(self):
        class A(DataModel):
            data_model_id = "test_register_duplicate"

        register(A)
        register(A)
        assert len(registered_data_models()) == 1
        assert A in registered_data_models()

    def test_register_data_model_duplicate_in_list(self):
        class A(DataModel):
            data_model_id = "test_register_duplicate"

        register([A, A])
        assert len(registered_data_models()) == 1

    def test_register_data_models(self):
        class A(DataModel):
            id = "a"

        class B(DataModel):
            id = "b"

        register([A, B])
        assert len(registered_data_models()) == 2
        assert A in registered_data_models()
        assert B in registered_data_models()

    def test_register_rule_and_data_model_same_list(self):
        class DataModelA(DataModel):
            id = "a"

        register([RuleA, DataModelA])
        assert len(registered_rules()) == 1
        assert RuleA in registered_rules()
        assert len(registered_data_models()) == 1
        assert DataModelA in registered_data_models()

    def test_invalid_argument(self):
        with pytest.raises(ValueError, match="argument must be a Rule or DataModel or an iterable of them not"):
            register(42)

    def test_invalid_argument_in_iterable(self):
        with pytest.raises(ValueError, match="argument must be a Rule or DataModel or an iterable of them not"):
            register([42])

    def test_invalid_argument_passed_along_rule(self):
        with pytest.raises(ValueError, match="argument must be a Rule or DataModel or an iterable of them not"):

            class A(Rule):
                log_types = [""]
                id = "a"
                default_severity = Severity.INFO

                def rule(self, _):
                    pass

            register([A, 42])

    def test_invalid_argument_passed_along_data_model(self):
        with pytest.raises(ValueError, match="argument must be a Rule or DataModel or an iterable of them not"):

            class A(DataModel):
                id = "a"

            register([A, 42])


class TestRegisteredRules:
    def test_supported_args(self) -> None:
        # this just statically checks that all the args are still there
        # mostly just prevents breaking changes. no need to assert anything
        registered_rules(
            log_types=None,
            id=None,
            create_alert=None,
            dedup_period_minutes=None,
            display_name=None,
            enabled=None,
            summary_attributes=None,
            tests=None,
            threshold=None,
            tags=None,
            reports=None,
            default_severity=None,
            default_description=None,
            default_reference=None,
            default_runbook=None,
            default_destinations=None,
        )

    def test_no_args(self) -> None:
        to_register = {RuleA, RuleB}
        register(to_register)
        registered = registered_rules()
        assert to_register == registered

    kwargs_a = [
        {"log_types": [LogType.OKTA_SYSTEM_LOG]},
        {"id": "rule_a"},
        {"create_alert": True},
        {"dedup_period_minutes": 60},
        {"display_name": "Rule A"},
        {"enabled": True},
        {"summary_attributes": ["foo"]},
        {"threshold": 1},
        {"tags": ["tag A"]},
        {"default_severity": Severity.INFO},
        {"default_description": "description A"},
        {"default_reference": "reference A"},
        {"default_runbook": "runbook A"},
        {"default_destinations": "destination A"},
    ]

    @pytest.mark.parametrize("kwarg_a", kwargs_a, ids=lambda x: str(next(iter(x))))
    def test_filter(self, kwarg_a) -> None:
        to_register = {RuleA, RuleB}
        register(to_register)
        registered = registered_rules(**kwarg_a)
        assert {RuleA} == registered


class TestGetRulesCaseInsensitiveFiltering(unittest.TestCase):
    def setUp(self):
        _RULE_REGISTRY.clear()
        _RULE_ID_TO_RULE_REGISTRY.clear()

    def tearDown(self):
        _RULE_REGISTRY.clear()

    def test_find_by_id(self) -> None:
        class TestRule(Rule):
            id = "TestRule"
            log_types = [LogType.PANTHER_AUDIT]
            default_severity = Severity.INFO

            def rule(self, _):
                pass

        register(TestRule)
        out = registered_rules(id="testrule")
        assert len(out) == 1
        assert out == {TestRule}

    def test_find_by_log_type(self) -> None:
        class TestRule(Rule):
            id = "TestRule"
            log_types = ["LogType.Test"]
            default_severity = Severity.INFO

            def rule(self, _):
                pass

        register(TestRule)
        out = registered_rules(log_types=["LoGtYpE.tEsT"])
        assert len(out) == 1
        assert out == {TestRule}
