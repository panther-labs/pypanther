import dataclasses
import json
from typing import Optional, Tuple
from unittest import TestCase

import pytest
from panther_core.detection import DetectionResult
from panther_core.enriched_event import PantherEvent
from panther_core.exceptions import FunctionReturnTypeError
from panther_core.rule import (
    MAX_DEDUP_STRING_SIZE,
    MAX_GENERATED_FIELD_SIZE,
    TRUNCATED_STRING_SUFFIX,
    TYPE_RULE,
)
from pydantic import ValidationError

from pypanther.base import (
    PANTHER_RULE_ALL_ATTRS,
    PantherRule,
    PantherRuleModel,
    PantherRuleTestFailure,
    PantherSeverity,
)
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.log_types import PantherLogType
from pypanther.rules.aws_cloudtrail_rules.aws_console_login_without_mfa import (
    AWSConsoleLoginWithoutMFA,
)


def test_pypanther_imports():
    """Ensures things import in the init file can be used directly from pypanther"""
    from pypanther import PantherDataModel  # noqa: F401
    from pypanther import PantherDataModelMapping  # noqa: F401
    from pypanther import PantherLogType  # noqa: F401
    from pypanther import PantherRule  # noqa: F401
    from pypanther import PantherRuleMock  # noqa: F401
    from pypanther import PantherRuleTest  # noqa: F401
    from pypanther import PantherSeverity  # noqa: F401
    from pypanther import get_panther_rules  # noqa: F401
    from pypanther import register  # noqa: F401
    from pypanther import registered_rules  # noqa: F401


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


def test_rule_inheritance():
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
        LogTypes = [PantherLogType.Panther_Audit, PantherLogType.AlphaSOC_Alert]
        Tags = ["old", "old2"]

    assert Test.RuleID == "old"
    assert Test.Severity == PantherSeverity.High
    assert Test.LogTypes == [PantherLogType.Panther_Audit, PantherLogType.AlphaSOC_Alert]
    assert Test.Tags == ["old", "old2"]

    Test.override(
        RuleID="new",
        Severity=PantherSeverity.Low,
        LogTypes=[PantherLogType.Amazon_EKS_Audit],
        Tags=Test.Tags + ["new"],
    )

    assert Test.RuleID == "new"
    assert Test.Severity == PantherSeverity.Low
    assert Test.LogTypes == [PantherLogType.Amazon_EKS_Audit]
    assert Test.Tags == ["old", "old2", "new"]


def test_panther_rule_fields_match():
    assert (
        set(PANTHER_RULE_ALL_ATTRS)
        == set(PantherRuleModel.__annotations__)
        == set(PantherRule.__annotations__)
        == set(PantherRule.override.__annotations__)
    )


def test_mock_patching():
    # ensure that mock patches work on the file the mock is defined in
    class TestRule(AWSConsoleLoginWithoutMFA):
        pass

    # ensure the base class has a mock defined
    assert len(TestRule.__base__.Tests[0].Mocks) > 0
    TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)


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
def test_run_tests_returns_aux_function_exceptions(func: str, caplog):
    class TestRule(AWSConsoleLoginWithoutMFA):
        def dedup(self, event):
            """dedup defaults to title so need to define this for test to work"""
            return "dedup"

    def aux(self, event):
        raise Exception("bad")

    setattr(TestRule, func, aux)

    with pytest.raises(PantherRuleTestFailure) as e:
        TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
    print(caplog.text)
    assert f"{func}() raised an exception, see log output for stacktrace" in caplog.text


def test_run_tests_returns_two_aux_function_exceptions(caplog):
    class TestRule(AWSConsoleLoginWithoutMFA):
        def runbook(self, event):
            raise Exception("bad")

        def severity(self, event):
            raise Exception("bad")

    with pytest.raises(PantherRuleTestFailure) as e:
        TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
    assert (
        "severity() and runbook() raised an exception, see log output for stacktrace" in caplog.text
    )


def test_run_tests_returns_all_aux_func_exceptions(caplog):
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

    class TestRule(AWSConsoleLoginWithoutMFA):
        pass

    def aux(self, event):
        raise Exception("bad")

    for func in funcs:
        setattr(TestRule, func, aux)

    with pytest.raises(PantherRuleTestFailure) as e:
        TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
    assert (
        "title(), description(), reference(), severity(), runbook(), destinations(), dedup() and alert_context() raised an exception, see log output for stacktrace"
        in caplog.text
    )


class TestValidation:
    def test_rule_missing_id(self):
        class rule(PantherRule):
            Severity = PantherSeverity.Info
            LogTypes = ["test"]

            def rule(self, event):
                return False

        with pytest.raises(ValidationError) as e:
            rule.validate()
        errors = e.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("RuleID",)
        assert errors[0]["msg"] == "Field required"

    def test_create_rule_missing_method(self) -> None:
        class rule(PantherRule):
            RuleID = "test_create_rule_missing_method"
            Severity = "Info"
            LogTypes = ["test"]

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
        class rule(PantherRule):
            RuleID = "test_rule_default_dedup_time"
            Severity = "INFO"

            def rule(self, event):
                return True

        assert 60 == rule.DedupPeriodMinutes

    def test_rule_tags(self) -> None:
        class rule(PantherRule):
            RuleID = "test_rule_default_dedup_time"
            Tags = ["tag2", "tag1"]
            Severity = "INFO"

            def rule(self, event):
                return True

        assert {"tag1", "tag2"} == set(rule.Tags)

    def test_rule_reports(self) -> None:
        class rule(PantherRule):
            RuleID = "test_rule_default_dedup_time"
            Reports = {"key1": ["value2", "value1"], "key2": ["value1"]}
            Severity = "INFO"

            def rule(self, event):
                return True

        assert {"key1": ["value2", "value1"], "key2": ["value1"]} == rule.Reports

    def test_rule_matches(self) -> None:
        class rule(PantherRule):
            RuleID = "test_rule_matches"
            DedupPeriodMinutes = 100
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_doesnt_match"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_dedup"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_restrict_dedup_size"
            Severity = "INFO"

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

        class rule(PantherRule):
            RuleID = "test_restrict_title_size"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_empty_dedup_result_to_default"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_throws_exception"
            Severity = "INFO"

            def rule(self, event):
                raise Exception("test")

        rule_result = rule().run(PantherEvent({}, None), {}, {})
        self.maxDiff = None
        assert False is rule_result.trigger_alert
        assert None is rule_result.dedup_output
        assert None is not rule_result.detection_exception

    def test_rule_invalid_rule_return(self) -> None:
        class rule(PantherRule):
            RuleID = "test_rule_invalid_rule_return"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_dedup_throws_exception"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_dedup_throws_exception"
            Severity = "INFO"

            def rule(self, event):
                return True

            def dedup(self, event):
                raise Exception("test")

        actual = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)

        assert actual.trigger_alert
        assert None is not actual.dedup_exception
        assert actual.errored

    def test_rule_invalid_dedup_return(self) -> None:
        class rule(PantherRule):
            RuleID = "test_rule_invalid_dedup_return"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_dedup_returns_empty_string"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_matches_with_title"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_title_throws_exception"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_invalid_title_return"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_title_returns_empty_string"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_alert_context"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_alert_context_invalid_return_value"
            Severity = "INFO"

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

        class rule(PantherRule):
            RuleID = "test_alert_context_too_big"
            Severity = "INFO"

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

        class rule(PantherRule):
            RuleID = "test_alert_context_immutable_event"
            Severity = "INFO"

            def rule(self, event):
                return True

            def alert_context(self, event):
                return {"headers": event["headers"], "get_params": event["query_string_args"]}

        event = {"headers": {"User-Agent": "Chrome"}, "query_string_args": [{"a": "1"}, {"b": "2"}]}

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
        class rule(PantherRule):
            RuleID = "test_alert_context_returns_full_event"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_all_generated_fields"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_invalid_severity"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_valid_severity_case_insensitive"
            Severity = "INFO"

            def rule(self, event):
                return True

            def severity(self, event):
                return "cRiTiCaL"

        result = rule().run(PantherEvent({}, None), {}, {}, batch_mode=False)
        assert "CRITICAL" == result.severity_output
        assert "INFO" == result.detection_severity

    def test_rule_with_default_severity(self) -> None:
        class rule(PantherRule):
            RuleID = "test_rule_with_default_severity"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_default_severity_case_insensitive"
            Severity = "MEDIUM"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_invalid_destinations_type"
            Severity = "INFO"

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
                    rule.RuleID, "destinations", "str"
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
        class rule(PantherRule):
            RuleID = "test_rule_with_severity_raising_exception_unit_test"
            Severity = "INFO"

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
        class rule(PantherRule):
            RuleID = "test_rule_with_severity_raising_exception_batch_mode"
            Severity = "INFO"

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
