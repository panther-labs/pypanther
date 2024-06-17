import pytest

from pypanther import testing
from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.log_types import PantherLogType
from pypanther.rules.aws_cloudtrail_rules.aws_console_login_without_mfa import (
    AWSConsoleLoginWithoutMFA,
)


class TestPrintFailedTestResults:
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
    def test_returns_aux_function_exceptions(self, func: str, caplog):
        class TestRule(AWSConsoleLoginWithoutMFA):
            def dedup(self, event):
                """dedup defaults to title so need to define this for test to work"""
                return "dedup"

        def aux(self, event):
            raise Exception("bad")

        setattr(TestRule, func, aux)

        results = TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])

        assert f"{func}() raised an exception, see log output for stacktrace" in caplog.text

    def test_returns_two_aux_function_exceptions(self, caplog):
        class TestRule(AWSConsoleLoginWithoutMFA):
            def runbook(self, event):
                raise Exception("bad")

            def severity(self, event):
                raise Exception("bad")

        results = TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])
        assert (
            "severity() and runbook() raised an exception, see log output for stacktrace"
            in caplog.text
        )

    def test_returns_all_aux_func_exceptions(self, caplog):
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

        results = TestRule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])
        assert (
            "title(), description(), reference(), severity(), runbook(), destinations(), dedup() and alert_context() raised an exception, see log output for stacktrace"
            in caplog.text
        )

    def test_runs_all_rule_tests(self, caplog):
        false_test_1 = PantherRuleTest(Name="false test 1", ExpectedResult=False, Log={})
        false_test_2 = PantherRuleTest(Name="false test 2", ExpectedResult=False, Log={})

        class Rule1(PantherRule):
            LogTypes = [PantherLogType.Panther_Audit]
            Severity = PantherSeverity.High
            RuleID = "Rule1"
            Tests = [false_test_1, false_test_2]

            def rule(self, event):
                return True

        class Rule2(PantherRule):
            LogTypes = [PantherLogType.Panther_Audit]
            Severity = PantherSeverity.High
            RuleID = "Rule2"
            Tests = [false_test_1, false_test_2]

            def rule(self, event):
                return True

        results = Rule1.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])
        assert "Rule1: test 'false test 1'" in caplog.text
        assert "Rule1: test 'false test 2'" in caplog.text

        results = Rule2.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])
        assert "Rule2: test 'false test 1'" in caplog.text
        assert "Rule2: test 'false test 2'" in caplog.text

    def test_returns_rule_func_exception(self, caplog):
        false_test_1 = PantherRuleTest(Name="false test 1", ExpectedResult=False, Log={})

        class Rule1(PantherRule):
            LogTypes = [PantherLogType.Panther_Audit]
            Severity = PantherSeverity.High
            RuleID = "Rule1"
            Tests = [false_test_1]

            def rule(self, event):
                raise Exception("bad")

        results = Rule1.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])
        assert "Rule1: Exception in test 'false test 1'" in caplog.text

    def test_all_tests_passed(self, caplog):
        false_test_1 = PantherRuleTest(Name="false test 1", ExpectedResult=False, Log={})

        class Rule1(PantherRule):
            LogTypes = [PantherLogType.Panther_Audit]
            Severity = PantherSeverity.High
            RuleID = "Rule1"
            Tests = [false_test_1]

            def rule(self, event):
                return False

        results = Rule1.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        testing.print_failed_test_results([results])
        assert "" == caplog.text
