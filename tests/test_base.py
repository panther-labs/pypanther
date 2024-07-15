import dataclasses
import json
from typing import Optional, Tuple
from unittest import TestCase

import pytest
from panther_core.detection import DetectionResult
from panther_core.enriched_event import PantherEvent
from panther_core.exceptions import FunctionReturnTypeError, UnknownDestinationError
from panther_core.rule import (
    MAX_DEDUP_STRING_SIZE,
    MAX_GENERATED_FIELD_SIZE,
    TRUNCATED_STRING_SUFFIX,
    TYPE_RULE,
)
from pydantic import ValidationError

from pypanther.base import RULE_ALL_ATTRS, Rule, RuleModel
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.log_types import LogType
from pypanther.rules.aws_cloudtrail_rules.aws_console_login_without_mfa import (
    AWSConsoleLoginWithoutMFA,
)
from pypanther.severity import Severity
from pypanther.unit_tests import RuleTest


def test_rule_inheritance():
    class Test(Rule):
        tags = ["test"]

        def rule(self, event):
            pass

    class Test2(Test):
        def rule(self, event):
            pass

    # values are inherited as copies
    assert Test2.tags == ["test"]
    assert Test.tags == ["test"]
    assert Test.tags is not Test2.tags

    # updates do not affect the parent or children
    Test2.tags.append("test2")
    assert Test2.tags == ["test", "test2"]
    assert Test.tags == ["test"]
    Test.tags.append("test3")
    assert Test2.tags == ["test", "test2"]
    assert Test.tags == ["test", "test3"]


def test_override():
    class Test(Rule):
        id = "old"
        default_severity = Severity.HIGH
        log_types = [LogType.Panther_Audit, LogType.AlphaSOC_Alert]
        tags = ["old", "old2"]

    assert Test.id == "old"
    assert Test.default_severity == Severity.HIGH
    assert Test.log_types == [
        LogType.Panther_Audit,
        LogType.AlphaSOC_Alert,
    ]
    assert Test.tags == ["old", "old2"]

    Test.override(
        id="new",
        default_severity=Severity.LOW,
        log_types=[LogType.Amazon_EKS_Audit],
        tags=Test.tags + ["new"],
    )

    assert Test.id == "new"
    assert Test.default_severity == Severity.LOW
    assert Test.log_types == [LogType.Amazon_EKS_Audit]
    assert Test.tags == ["old", "old2", "new"]


def test_panther_rule_fields_match():
    assert (
        set(RULE_ALL_ATTRS)
        == set(RuleModel.__annotations__)
        == set(Rule.__annotations__)
        == set(Rule.override.__annotations__)
    )


def test_mock_patching():
    # ensure that mock patches work on the file the mock is defined in
    class TestRule(AWSConsoleLoginWithoutMFA):
        pass

    # ensure the base class has a mock defined
    assert len(TestRule.__base__.tests[0].mocks) > 0
    TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)


class TestRunningTests:
    @pytest.mark.parametrize(
        "func",
        [
            "title",
            "description",
            "reference",
            "severity",
            "runbook",
            "destinations",
            "dedup",
            "alert_context",
        ],
    )
    def test_returns_aux_function_exceptions(self, func: str):
        class TestRule(Rule):
            id = "TestRule"
            default_severity = Severity.HIGH
            log_types = [LogType.AlphaSOC_Alert]
            tests = [RuleTest(name="test", expected_result=True, log={})]

            def rule(self, event):
                return True

            def dedup(self, event):
                """dedup defaults to title so need to define this for test to work"""
                return "dedup"

        def aux(self, event):
            raise Exception("bad")

        setattr(TestRule, func, aux)

        results = TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        assert len(results) == 1
        assert not results[0].passed
        assert "bad" in str(getattr(results[0].detection_result, f"{func}_exception"))

    def test_returns_two_aux_function_exceptions(self):
        class TestRule(Rule):
            id = "TestRule"
            default_severity = Severity.HIGH
            log_types = [LogType.AlphaSOC_Alert]
            tests = [RuleTest(name="test", expected_result=True, log={})]

            def rule(self, event):
                return True

            def runbook(self, event):
                raise Exception("bad")

            def severity(self, event):
                raise Exception("bad")

        results = TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        assert len(results) == 1
        assert not results[0].passed
        for func in ["runbook", "severity"]:
            assert "bad" in str(getattr(results[0].detection_result, f"{func}_exception"))

    def test_returns_all_aux_func_exceptions(self):
        funcs = [
            "title",
            "description",
            "reference",
            "severity",
            "runbook",
            "destinations",
            "dedup",
            "alert_context",
        ]

        class TestRule(Rule):
            id = "TestRule"
            default_severity = Severity.HIGH
            log_types = [LogType.AlphaSOC_Alert]
            tests = [RuleTest(name="test", expected_result=True, log={})]

            def rule(self, event):
                return True

        def aux(self, event):
            raise Exception("bad")

        for func in funcs:
            setattr(TestRule, func, aux)

        results = TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        assert len(results) == 1
        assert not results[0].passed
        for func in funcs:
            assert "bad" in str(getattr(results[0].detection_result, f"{func}_exception"))

    def test_runs_all_rule_tests(self):
        false_test_1 = RuleTest(name="false test 1", expected_result=False, log={})
        false_test_2 = RuleTest(name="false test 2", expected_result=False, log={})

        class Rule1(Rule):
            log_types = [LogType.Panther_Audit]
            default_severity = Severity.HIGH
            id = "Rule1"
            tests = [false_test_1, false_test_2]

            def rule(self, event):
                return True

        class Rule2(Rule):
            log_types = [LogType.Panther_Audit]
            default_severity = Severity.HIGH
            id = "Rule2"
            tests = [false_test_1, false_test_2]

            def rule(self, event):
                return True

        results = Rule1.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        assert len(results) == 2
        assert not results[0].passed
        assert not results[1].passed
        Rule2.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        assert len(results) == 2
        assert not results[0].passed
        assert not results[1].passed

    def test_returns_rule_func_exception(self):
        false_test_1 = RuleTest(name="false test 1", expected_result=False, log={})

        class Rule1(Rule):
            log_types = [LogType.Panther_Audit]
            default_severity = Severity.HIGH
            id = "Rule1"
            tests = [false_test_1]

            def rule(self, event):
                raise Exception("bad")

        results = Rule1.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        assert len(results) == 1
        assert not results[0].passed
        assert "bad" in str(results[0].detection_result.detection_exception)


class TestValidation:
    def test_rule_missing_id(self):
        class rule(Rule):
            default_severity = Severity.INFO
            log_types = ["test"]

            def rule(self, event):
                return False

        with pytest.raises(ValidationError) as e:
            rule.validate()
        errors = e.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("id",)
        assert errors[0]["msg"] == "Field required"

    def test_create_rule_missing_method(self) -> None:
        class rule(Rule):
            id = "test_create_rule_missing_method"
            default_severity = Severity.INFO
            log_types = ["test"]

            def another_method(self, event):
                return False

        with pytest.raises(TypeError) as e:
            rule.validate()
        assert e.value.args == ("Can't instantiate abstract class rule with abstract method rule",)


class TestRule(TestCase):
    # TODO: update type annotation for checked objects to be dataclass in Python 3.8+
    def assertDetectionResultEqual(
        self,
        first: DetectionResult,
        second: DetectionResult,
        fields_as_string: Optional[Tuple[str, ...]] = None,
    ) -> None:
        """
        Compare two dataclass instances by first converting them to dictionaries.
        In order to allow comparison for non-comparable objects, such as exception instances,
        a list of fields to be converted to their string representation can be given.
        """
        self.assertIsInstance(first, type(second))
        fields_as_string = fields_as_string or ()
        first = dataclasses.asdict(first)
        second = dataclasses.asdict(second)
        for string_repr_field in fields_as_string:
            first[string_repr_field] = str(first[string_repr_field])
            second[string_repr_field] = str(second[string_repr_field])
        assert first == second

    def test_rule_default_dedup_time(self) -> None:
        class rule(Rule):
            id = "test_rule_default_dedup_time"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

        assert 60 == rule.dedup_period_minutes

    def test_rule_tags(self) -> None:
        class rule(Rule):
            id = "test_rule_default_dedup_time"
            default_tags = ["tag2", "tag1"]
            default_severity = Severity.INFO

            def rule(self, event):
                return True

        assert {"tag1", "tag2"} == set(rule.default_tags)

    def test_rule_reports(self) -> None:
        class rule(Rule):
            id = "test_rule_default_dedup_time"
            default_reports = {"key1": ["value2", "value1"], "key2": ["value1"]}
            default_severity = Severity.INFO

            def rule(self, event):
                return True

        assert {
            "key1": ["value2", "value1"],
            "key2": ["value1"],
        } == rule.default_reports

    def test_rule_matches(self) -> None:
        class rule(Rule):
            id = "test_rule_matches"
            dedup_period_minutes = 100
            default_severity = Severity.INFO

            def rule(self, event):
                return True

        expected_rule = DetectionResult(
            detection_id="test_rule_matches",
            trigger_alert=True,
            dedup_output="test_rule_matches",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            severity_output="INFO",
            alert_context_output="{}",
            title_output="test_rule_matches",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_doesnt_match(self) -> None:
        class rule(Rule):
            id = "test_rule_doesnt_match"
            default_severity = Severity.INFO

            def rule(self, event):
                return False

        expected_rule = DetectionResult(
            trigger_alert=False,
            detection_id="test_rule_doesnt_match",
            detection_output=False,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        self.assertEqual(expected_rule, rule().run(PantherEvent({}, None), {}, {}))

    def test_rule_with_dedup(self) -> None:
        class rule(Rule):
            id = "test_rule_with_dedup"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                return "testdedup"

        expected_rule = DetectionResult(
            detection_id="test_rule_with_dedup",
            trigger_alert=True,
            detection_output=True,
            dedup_output="testdedup",
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            severity_output="INFO",
            alert_context_output="{}",
            title_output="test_rule_with_dedup",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_restrict_dedup_size(self) -> None:
        class rule(Rule):
            id = "test_restrict_dedup_size"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                return "".join("a" for _ in range(MAX_DEDUP_STRING_SIZE + 1))

        expected_dedup_string_prefix = "".join(
            "a" for _ in range(MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX))
        )
        expected_rule = DetectionResult(
            detection_id="test_restrict_dedup_size",
            trigger_alert=True,
            dedup_output=expected_dedup_string_prefix + TRUNCATED_STRING_SUFFIX,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            title_output="test_restrict_dedup_size",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
            severity_output="INFO",
            description_output="",
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_restrict_title_size(self) -> None:
        class rule(Rule):
            id = "test_restrict_title_size"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                return "test"

            def title(self, event):
                return "".join("a" for i in range(MAX_GENERATED_FIELD_SIZE + 1))

        expected_title_string_prefix = "".join(
            "a" for _ in range(MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX))
        )
        expected_rule = DetectionResult(
            detection_id="test_restrict_title_size",
            trigger_alert=True,
            dedup_output="test",
            title_output=expected_title_string_prefix + TRUNCATED_STRING_SUFFIX,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_empty_dedup_result_to_default(self) -> None:
        class rule(Rule):
            id = "test_empty_dedup_result_to_default"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                return ""

        expected_rule = DetectionResult(
            detection_id="test_empty_dedup_result_to_default",
            trigger_alert=True,
            dedup_output="test_empty_dedup_result_to_default",
            title_output="test_empty_dedup_result_to_default",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_throws_exception(self) -> None:
        class rule(Rule):
            id = "test_rule_throws_exception"
            default_severity = Severity.INFO

            def rule(self, event):
                raise Exception("test")

        rule_result = rule().run(PantherEvent({}, None), {}, {})
        self.maxDiff = None
        assert False is rule_result.trigger_alert
        assert None is rule_result.dedup_output
        assert None is not rule_result.detection_exception

    def test_rule_invalid_rule_return(self) -> None:
        class rule(Rule):
            id = "test_rule_invalid_rule_return"
            default_severity = Severity.INFO

            def rule(self, event):
                return "test"

        rule_result = rule().run(PantherEvent({}, None), {}, {})
        assert False is rule_result.trigger_alert
        assert None is rule_result.dedup_output
        assert True is rule_result.errored

        expected_short_msg = "FunctionReturnTypeError('detection [test_rule_invalid_rule_return] method [rule] returned [str], expected [bool]')"
        assert expected_short_msg == rule_result.short_error_message
        assert rule_result.error_type == "FunctionReturnTypeError"

    def test_dedup_throws_exception(self) -> None:
        class rule(Rule):
            id = "test_dedup_throws_exception"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                raise Exception("test")

        expected_rule = DetectionResult(
            detection_id="test_dedup_throws_exception",
            trigger_alert=True,
            dedup_output="test_dedup_throws_exception",
            title_output="test_dedup_throws_exception",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_dedup_exception_batch_mode(self) -> None:
        class rule(Rule):
            id = "test_dedup_throws_exception"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                raise Exception("test")

        actual = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)

        assert actual.trigger_alert
        assert None is not actual.dedup_exception
        assert actual.errored

    def test_rule_invalid_dedup_return(self) -> None:
        class rule(Rule):
            id = "test_rule_invalid_dedup_return"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                return {}

        expected_rule = DetectionResult(
            detection_id="test_rule_invalid_dedup_return",
            trigger_alert=True,
            dedup_output="test_rule_invalid_dedup_return",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            title_output="test_rule_invalid_dedup_return",
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        assert expected_rule == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_dedup_returns_empty_string(self) -> None:
        class rule(Rule):
            id = "test_rule_dedup_returns_empty_string"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def dedup(self, event):
                return ""

        expected_result = DetectionResult(
            detection_id="test_rule_dedup_returns_empty_string",
            trigger_alert=True,
            dedup_output="test_rule_dedup_returns_empty_string",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            title_output="test_rule_dedup_returns_empty_string",
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_matches_with_title_without_dedup(self) -> None:
        class rule(Rule):
            id = "test_rule_matches_with_title"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def title(self, event):
                return "title"

        expected_result = DetectionResult(
            detection_id="test_rule_matches_with_title",
            trigger_alert=True,
            dedup_output="title",
            title_output="title",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_title_throws_exception(self) -> None:
        class rule(Rule):
            id = "test_rule_title_throws_exception"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def title(self, event):
                raise Exception("test")

        expected_result = DetectionResult(
            detection_id="test_rule_title_throws_exception",
            trigger_alert=True,
            dedup_output="test_rule_title_throws_exception",
            title_output="test_rule_title_throws_exception",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            alert_context_output="{}",
            destinations_output=["SKIP"],
            runbook_output="",
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_invalid_title_return(self) -> None:
        class rule(Rule):
            id = "test_rule_invalid_title_return"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def title(self, event):
                return {}

        expected_result = DetectionResult(
            detection_id="test_rule_invalid_title_return",
            trigger_alert=True,
            dedup_output="test_rule_invalid_title_return",
            title_output="test_rule_invalid_title_return",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
            severity_output="INFO",
            alert_context_output="{}",
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_rule_title_returns_empty_string(self) -> None:
        class rule(Rule):
            id = "test_rule_title_returns_empty_string"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def title(self, event):
                return ""

        expected_result = DetectionResult(
            detection_id="test_rule_title_returns_empty_string",
            trigger_alert=True,
            dedup_output="defaultDedupString:test_rule_title_returns_empty_string",
            title_output="",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
            severity_output="INFO",
            alert_context_output="{}",
        )
        self.maxDiff = None
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_alert_context(self) -> None:
        class rule(Rule):
            id = "test_alert_context"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {"string": "string", "int": 1, "nested": {}}

        expected_result = DetectionResult(
            detection_id="test_alert_context",
            trigger_alert=True,
            dedup_output="test_alert_context",
            title_output="test_alert_context",
            alert_context_output='{"string": "string", "int": 1, "nested": {}}',
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_alert_context_invalid_return_value(self) -> None:
        class rule(Rule):
            id = "test_alert_context_invalid_return_value"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return ""

        expected_alert_context = json.dumps(
            {
                "_error": "FunctionReturnTypeError('detection [test_alert_context_invalid_return_value] method [alert_context] returned [str], expected [Mapping]')"
            }
        )
        expected_result = DetectionResult(
            detection_id="test_alert_context_invalid_return_value",
            trigger_alert=True,
            dedup_output="test_alert_context_invalid_return_value",
            title_output="test_alert_context_invalid_return_value",
            alert_context_output=expected_alert_context,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_alert_context_too_big(self) -> None:
        # Function should generate alert_context exceeding limit

        class rule(Rule):
            id = "test_alert_context_too_big"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                test_dict = {}
                for i in range(300000):
                    test_dict[str(i)] = "value"
                return test_dict

        expected_alert_context = json.dumps(
            {
                "_error": "alert_context size is [5588890] characters, bigger than maximum of [204800] characters"
            }
        )
        expected_result = DetectionResult(
            detection_id="test_alert_context_too_big",
            trigger_alert=True,
            dedup_output="test_alert_context_too_big",
            title_output="test_alert_context_too_big",
            alert_context_output=expected_alert_context,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
        )
        assert expected_result == rule().run(PantherEvent({}, None), {}, {})

    def test_alert_context_immutable_event(self) -> None:
        class rule(Rule):
            id = "test_alert_context_immutable_event"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {
                    "headers": event["headers"],
                    "get_params": event["query_string_args"],
                }

        event = {
            "headers": {"User-Agent": "Chrome"},
            "query_string_args": [{"a": "1"}, {"b": "2"}],
        }

        expected_alert_context = json.dumps(
            {"headers": event["headers"], "get_params": event["query_string_args"]}
        )
        expected_result = DetectionResult(
            detection_id="test_alert_context_immutable_event",
            trigger_alert=True,
            dedup_output="test_alert_context_immutable_event",
            title_output="test_alert_context_immutable_event",
            alert_context_output=expected_alert_context,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
        )
        assert expected_result == rule().run(PantherEvent(event, None), {}, {})

    def test_alert_context_returns_full_event(self) -> None:
        class rule(Rule):
            id = "test_alert_context_returns_full_event"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return event

        event = {"test": "event"}

        expected_alert_context = json.dumps(event)
        expected_result = DetectionResult(
            detection_id="test_alert_context_returns_full_event",
            trigger_alert=True,
            dedup_output="test_alert_context_returns_full_event",
            title_output="test_alert_context_returns_full_event",
            alert_context_output=expected_alert_context,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            severity_output="INFO",
            runbook_output="",
            destinations_output=["SKIP"],
        )
        assert expected_result == rule().run(PantherEvent(event, None), {}, {})

    # Generated Fields Tests
    def test_rule_with_all_generated_fields(self) -> None:
        class rule(Rule):
            id = "test_rule_with_all_generated_fields"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {}

            def title(self, event):
                return "test_rule_with_all_generated_fields"

            def description(self, event):
                return "test description"

            def severity(self, event):
                return "HIGH"

            def reference(self, event):
                return "test reference"

            def runbook(self, event):
                return "test runbook"

            def destinations(self, event):
                return []

        expected_result = DetectionResult(
            detection_id="test_rule_with_all_generated_fields",
            trigger_alert=True,
            alert_context_output="{}",
            title_output="test_rule_with_all_generated_fields",
            dedup_output="test_rule_with_all_generated_fields",
            description_output="test description",
            severity_output="HIGH",
            reference_output="test reference",
            runbook_output="test runbook",
            destinations_output=["SKIP"],
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
        )
        self.maxDiff = None
        assert expected_result == rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)

    def test_rule_with_invalid_severity(self) -> None:
        class rule(Rule):
            id = "test_rule_with_invalid_severity"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {}

            def title(self, event):
                return "test_rule_with_invalid_severity"

            def severity(self, event):
                return "CRITICAL-ISH"

        expected_result = DetectionResult(
            detection_id="test_rule_with_invalid_severity",
            trigger_alert=True,
            alert_context_output="{}",
            title_output="test_rule_with_invalid_severity",
            dedup_output="test_rule_with_invalid_severity",
            severity_output="INFO",
            severity_exception=AssertionError(
                "Expected severity to be any of the following: [['INFO', 'LOW', 'MEDIUM', 'HIGH', "
                "'CRITICAL']], got [CRITICAL-ISH] instead."
            ),
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
        )
        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        self.assertDetectionResultEqual(
            expected_result, result, fields_as_string=("severity_exception",)
        )
        self.assertTrue(result.errored)

    def test_rule_with_valid_severity_case_insensitive(self) -> None:
        class rule(Rule):
            id = "test_rule_with_valid_severity_case_insensitive"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def severity(self, event):
                return "cRiTiCaL"

        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        assert "CRITICAL" == result.severity_output
        assert "INFO" == result.detection_severity

    def test_rule_with_default_severity(self) -> None:
        class rule(Rule):
            id = "test_rule_with_default_severity"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {}

            def title(self, event):
                return "test_rule_with_default_severity"

            def severity(self, event):
                return "DEFAULT"

        expected_result = DetectionResult(
            trigger_alert=True,
            detection_id="test_rule_with_default_severity",
            alert_context_output="{}",
            title_output="test_rule_with_default_severity",
            dedup_output="test_rule_with_default_severity",
            severity_output="INFO",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
        )
        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        assert expected_result == result

    def test_rule_with_default_severity_case_insensitive(self) -> None:
        class rule(Rule):
            id = "test_rule_with_default_severity_case_insensitive"
            default_severity = "MEDIUM"

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {}

            def title(self, event):
                return "test_rule_with_default_severity_case_insensitive"

            def severity(self, event):
                return "default"

        expected_result = DetectionResult(
            trigger_alert=True,
            detection_id="test_rule_with_default_severity_case_insensitive",
            alert_context_output="{}",
            title_output="test_rule_with_default_severity_case_insensitive",
            dedup_output="test_rule_with_default_severity_case_insensitive",
            severity_output="MEDIUM",
            detection_output=True,
            detection_severity="MEDIUM",
            detection_type=TYPE_RULE,
            description_output="",
            runbook_output="",
            reference_output="",
            destinations_output=["SKIP"],
        )
        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        assert expected_result == result

    def test_rule_with_invalid_destinations_type(self) -> None:
        class rule(Rule):
            id = "test_rule_with_invalid_destinations_type"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {}

            def title(self, event):
                return "test_rule_with_invalid_destinations_type"

            def severity(self, event):
                return "cRiTiCaL"

            def destinations(self, event):
                return "bad input"

        expected_result = DetectionResult(
            detection_id="test_rule_with_invalid_destinations_type",
            trigger_alert=True,
            alert_context_output="{}",
            title_output="test_rule_with_invalid_destinations_type",
            dedup_output="test_rule_with_invalid_destinations_type",
            severity_output="CRITICAL",
            destinations_exception=FunctionReturnTypeError(
                "detection [{}] method [{}] returned [{}], expected a list".format(
                    rule.id, "destinations", "str"
                )
            ),
            destinations_output=None,
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            runbook_output="",
        )
        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        self.assertDetectionResultEqual(
            expected_result, result, fields_as_string=("destinations_exception",)
        )
        self.assertTrue(result.errored)
        self.assertIsNotNone(result.destinations_exception)

    def test_rule_with_severity_raising_exception_unit_test(self) -> None:
        class rule(Rule):
            id = "test_rule_with_severity_raising_exception_unit_test"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def title(self, event):
                return "test_rule_with_severity_raising_exception_unit_test"

            def severity(self, event):
                raise AssertionError("something bad happened")

        expected_result = DetectionResult(
            detection_id="test_rule_with_severity_raising_exception_unit_test",
            trigger_alert=True,
            title_output="test_rule_with_severity_raising_exception_unit_test",
            dedup_output="test_rule_with_severity_raising_exception_unit_test",
            severity_exception=AssertionError("something bad happened"),
            detection_output=True,
            detection_severity="INFO",
            severity_output="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        assert True is result.errored
        assert None is not result.severity_exception
        # Exception instances cannot be compared
        self.assertDetectionResultEqual(
            expected_result, result, fields_as_string=("severity_exception",)
        )

    def test_rule_with_severity_raising_exception_batch_mode(self) -> None:
        class rule(Rule):
            id = "test_rule_with_severity_raising_exception_batch_mode"
            default_severity = Severity.INFO

            def rule(self, event):
                return True

            def title(self, event):
                return "test_rule_with_severity_raising_exception_batch_mode"

            def severity(self, event):
                raise AssertionError("something bad happened")

        expected_result = DetectionResult(
            detection_id="test_rule_with_severity_raising_exception_batch_mode",
            trigger_alert=True,
            title_output="test_rule_with_severity_raising_exception_batch_mode",
            dedup_output="test_rule_with_severity_raising_exception_batch_mode",
            severity_output="INFO",
            detection_output=True,
            detection_severity="INFO",
            detection_type=TYPE_RULE,
            description_output="",
            reference_output="",
            runbook_output="",
            destinations_output=["SKIP"],
            alert_context_output="{}",
        )
        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=True)
        assert expected_result == result

    def test_invalid_destination_during_run(self) -> None:
        class TestRule(Rule):
            id = "TestRule"
            log_types = [LogType.Panther_Audit]
            default_severity = Severity.CRITICAL

            def rule(self, event: PantherEvent) -> bool:
                return True

            def destinations(self, event) -> list[str]:
                return ["boom", "bam"]

        result = TestRule().run(
            PantherEvent({}),
            {},
            {"boom": FakeDestination(destination_display_name="boom", destination_id="123")},
            False,
        )
        assert isinstance(result.destinations_exception, UnknownDestinationError)
        assert result.destinations_output == ["123"]

    def test_invalid_destination_during_test(self) -> None:
        class TestRule(Rule):
            id = "TestRule"
            log_types = [LogType.Panther_Audit]
            default_severity = Severity.CRITICAL

            def rule(self, event: PantherEvent) -> bool:
                return True

            def destinations(self, event) -> list[str]:
                return ["boom", "bam"]

        result = TestRule().run_test(
            RuleTest(name="test", expected_result=True, log={}),
            DATA_MODEL_CACHE.data_model_of_logtype,
        )
        assert result.detection_result.destinations_exception is None
        assert result.detection_result.destinations_output == []


@dataclasses.dataclass
class FakeDestination:
    """Stub class as a replacement for the Destination class
    that wraps alert output metadata."""

    destination_id: str
    destination_display_name: str
