import contextlib
import os.path
from pathlib import Path
from typing import Any

import pytest
from panther_core import PantherEvent

from pypanther import testing
from pypanther.base import Rule, RuleTest, Severity
from pypanther.cache import data_model_cache
from pypanther.log_types import LogType
from pypanther.main import setup_parser

get_data_model = data_model_cache().data_model_of_logtype


class Test(Rule):
    id = "Test"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.LOW
    return_value = False

    def rule(self, event: PantherEvent) -> bool:
        return self.return_value

    def alert_context(self, event: PantherEvent) -> dict:
        return {"hi": "bye"}


class Sub1(Test):
    id = "Sub1"
    tests = [
        RuleTest(name="test1", expected_result=True, log={}),
        RuleTest(name="test2", expected_result=False, log={}),
        RuleTest(name="test3", expected_result=False, expected_severity=Severity.HIGH, log={}),
    ]


class Sub2(Test):
    id = "Sub2"
    tests = [
        RuleTest(name="test4", expected_result=True, log={}),
        RuleTest(name="test5", expected_result=False, log={}),
        RuleTest(name="test6", expected_result=False, expected_severity=Severity.HIGH, log={}),
    ]


class TestPrintRuleTestResults:
    def test_no_tests(self, capsys) -> None:
        Test.return_value = False
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        std = capsys.readouterr()
        assert std.out == ""
        assert std.err == ""

    def test_all_pass(self, capsys) -> None:
        Test.return_value = False
        Test.tests = [RuleTest(name="test", expected_result=False, log={})]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        std = capsys.readouterr()
        assert std.out == ""
        assert std.err == ""

    def test_rule_func_failure(self, capsys) -> None:
        Test.return_value = False
        Test.tests = [RuleTest(name="test", expected_result=True, log={})]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_severity_func_failure(self, capsys) -> None:
        Test.return_value = True
        Test.tests = [RuleTest(name="test", expected_severity=Severity.HIGH, expected_result=True, log={})]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected severity() to return 'HIGH', but got 'LOW'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_alert_context_func_failure(self, capsys) -> None:
        Test.return_value = True
        Test.tests = [RuleTest(name="test", expected_alert_context={"sad": "time"}, expected_result=True, log={})]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected alert_context() to return '{'sad': 'time'}', but got '{\"hi\": \"bye\"}'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_many_func_failures(self, capsys) -> None:
        Test.return_value = True
        Test.tests = [
            RuleTest(
                name="test",
                expected_alert_context={"sad": "time"},
                expected_severity=Severity.HIGH,
                expected_result=False,
                log={},
            ),
        ]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected rule() to return 'False', but got 'True'\n"
            "     - Expected severity() to return 'HIGH', but got 'LOW'\n"
            "     - Expected alert_context() to return '{'sad': 'time'}', but got '{\"hi\": \"bye\"}'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_many_tests(self, capsys) -> None:
        Test.return_value = True
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=True, expected_title="bad", log={}),
        ]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test1\n"
            "     - Expected rule() to return 'False', but got 'True'\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test2\n"
            "     - Expected title() to return 'bad', but got 'Test'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_both_pass_and_fail(self, capsys) -> None:
        Test.return_value = False
        Test.tests = [
            RuleTest(name="test1", expected_result=True, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        testing.print_rule_test_results(False, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test2\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_both_pass_and_fail_verbose(self, capsys) -> None:
        Test.return_value = False
        Test.tests = [
            RuleTest(name="test1", expected_result=True, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        testing.print_rule_test_results(True, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test2\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "   \x1b[92mPASS\x1b[0m: test\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_no_tests_verbose(self, capsys) -> None:
        Test.return_value = False
        Test.tests = []
        testing.print_rule_test_results(True, Test.id, Test.run_tests(get_data_model))

        exp = "\x1b[95mTest\x1b[0m:\n   SKIP: rule had no tests\n\n"
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_pass_tests_verbose(self, capsys) -> None:
        Test.return_value = False
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        testing.print_rule_test_results(True, Test.id, Test.run_tests(get_data_model))

        exp = "\x1b[95mTest\x1b[0m:\n   \x1b[92mPASS\x1b[0m: test1\n   \x1b[92mPASS\x1b[0m: test2\n\n"
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""


class TestPrintFailureSummary:
    def test_no_tests(self, capsys) -> None:
        Test.tests = []
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        testing.print_failed_test_summary(test_results)

        exp = ""
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_all_pass(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        testing.print_failed_test_summary(test_results)

        exp = ""
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_some_failures(self, capsys) -> None:
        Test.tests = []

        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2, Sub2.run_tests(get_data_model))
        testing.print_failed_test_summary(test_results)

        exp = (
            "\x1b[95mFailed Tests\x1b[0m:\n"
            "   1. \x1b[1mSub1\x1b[0m:\n"
            "     - test1\n"
            "     - test3\n"
            "   2. \x1b[1mSub2\x1b[0m:\n"
            "     - test4\n"
            "     - test6\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""


class TestPrintTestSummary:
    def test_no_tests(self, capsys) -> None:
        Test.tests = []
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        testing.print_test_summary(test_results)

        exp = (
            "\x1b[95mTest Summary\x1b[0m\n"
            "   Skipped rules:   1 \n"
            "   Passed rules:    0 \n"
            "   \x1b[4mFailed rules:    0\x1b[0m \n"
            "   Total rules:     1\n"
            "\n"
            "   Passed tests:    0\n"
            "   \x1b[4mFailed tests:    0\x1b[0m\n"
            "   Total tests:     0\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_all_pass(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        testing.print_test_summary(test_results)

        exp = (
            "\x1b[95mTest Summary\x1b[0m\n"
            "   Skipped rules:   0 \n"
            "   Passed rules:    1 \n"
            "   \x1b[4mFailed rules:    0\x1b[0m \n"
            "   Total rules:     1\n"
            "\n"
            "   Passed tests:    2\n"
            "   \x1b[4mFailed tests:    0\x1b[0m\n"
            "   Total tests:     2\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_some_failures(self, capsys) -> None:
        Test.tests = []

        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2, Sub2.run_tests(get_data_model))
        testing.print_test_summary(test_results)

        exp = (
            "\x1b[95mTest Summary\x1b[0m\n"
            "   Skipped rules:   1 \n"
            "   Passed rules:    0 \n"
            "   \x1b[4mFailed rules:    2\x1b[0m \n"
            "   Total rules:     3\n"
            "\n"
            "   Passed tests:    2\n"
            "   \x1b[4mFailed tests:    4\x1b[0m\n"
            "   Total tests:     6\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""


class TestGetTestResultsAsDict:
    def test_no_tests(self) -> None:
        Test.tests = []
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        out = testing.get_test_results_as_dict(test_results, False)

        exp: dict[str, Any] = {}
        assert out == exp

    def test_no_tests_verbose(self) -> None:
        Test.tests = []
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        out = testing.get_test_results_as_dict(test_results, True)

        exp: dict[str, Any] = {"Test": []}
        assert out == exp

    def test_all_pass(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        out = testing.get_test_results_as_dict(test_results, False)

        exp: dict[str, Any] = {}
        assert out == exp

    def test_all_pass_verbose(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        out = testing.get_test_results_as_dict(test_results, True)

        exp = {
            "Test": [
                {
                    "exceptions": [],
                    "failed_results": [],
                    "passed": True,
                    "test_name": "test1",
                },
                {
                    "exceptions": [],
                    "failed_results": [],
                    "passed": True,
                    "test_name": "test2",
                },
            ],
        }
        assert out == exp

    def test_some_failures(self) -> None:
        Test.tests = []

        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2, Sub2.run_tests(get_data_model))
        out = testing.get_test_results_as_dict(test_results, False)

        rule_func_failure = {"expected": True, "func": "rule", "matched": False, "output": True}
        sev_func_failure = {"expected": Severity.HIGH, "func": "severity", "matched": False, "output": Severity.HIGH}

        exp = {
            "Sub1": [
                {
                    "test_name": "test1",
                    "exceptions": [],
                    "failed_results": [rule_func_failure],
                    "passed": False,
                },
                {
                    "test_name": "test3",
                    "exceptions": [],
                    "failed_results": [sev_func_failure],
                    "passed": False,
                },
            ],
            "Sub2": [
                {
                    "test_name": "test4",
                    "exceptions": [],
                    "failed_results": [rule_func_failure],
                    "passed": False,
                },
                {
                    "test_name": "test6",
                    "exceptions": [],
                    "failed_results": [sev_func_failure],
                    "passed": False,
                },
            ],
        }
        assert out == exp

    def test_some_failures_verbose(self) -> None:
        Test.tests = []

        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2, Sub2.run_tests(get_data_model))
        out = testing.get_test_results_as_dict(test_results, True)

        rule_func_failure = {"expected": True, "func": "rule", "matched": False, "output": True}
        sev_func_failure = {"expected": Severity.HIGH, "func": "severity", "matched": False, "output": Severity.HIGH}

        exp = {
            "Sub1": [
                {
                    "exceptions": [],
                    "failed_results": [],
                    "passed": True,
                    "test_name": "test2",
                },
                {
                    "exceptions": [],
                    "failed_results": [rule_func_failure],
                    "passed": False,
                    "test_name": "test1",
                },
                {
                    "exceptions": [],
                    "failed_results": [sev_func_failure],
                    "passed": False,
                    "test_name": "test3",
                },
            ],
            "Sub2": [
                {
                    "exceptions": [],
                    "failed_results": [],
                    "passed": True,
                    "test_name": "test5",
                },
                {
                    "exceptions": [],
                    "failed_results": [rule_func_failure],
                    "passed": False,
                    "test_name": "test4",
                },
                {
                    "exceptions": [],
                    "failed_results": [sev_func_failure],
                    "passed": False,
                    "test_name": "test6",
                },
            ],
            "Test": [],
        }
        assert out == exp


class TestGetFailedTestSummaryAsDict:
    def test_some_failures_verbose(self) -> None:
        Test.tests = []

        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2, Sub2.run_tests(get_data_model))
        out = testing.get_failed_test_summary_as_dict(test_results)

        exp = [
            {
                "failed_tests": ["test1", "test3"],
                "num_failed_tests": 2,
                "rule_id": "Sub1",
            },
            {
                "failed_tests": ["test4", "test6"],
                "num_failed_tests": 2,
                "rule_id": "Sub2",
            },
        ]
        assert out == exp


class TestGetTestSummaryAsDict:
    def test_some_failures_verbose(self) -> None:
        Test.tests = []

        test_results = testing.TestResults()
        test_results.add_test_results(Test, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2, Sub2.run_tests(get_data_model))
        out = testing.get_test_summary_as_dict(test_results)

        exp = {
            "failed_rules": 2,
            "failed_tests": 4,
            "passed_rules": 0,
            "passed_tests": 2,
            "skipped_rules": 1,
            "total_rules": 3,
            "total_tests": 6,
        }
        assert out == exp


class TestRun:
    FILTER_ARGS = [
        ""  # no filter
        "--log-types a b",
        "--id abc",
        "--create-alert true",
        "--create-alert false",
        "--dedup-period-minutes 5",
        "--display-name 5",
        "--enabled true",
        "--enabled false",
        "--summary-attributes a b",
        "--threshold 9",
        "--tags a b",
        "--default-severity low",
        "--default-description desc",
        "--default-reference ref",
        "--default-runbook run",
        "--default-destinations a b",
        "--test-names a b",
    ]

    @pytest.mark.parametrize("cmd", [f"test {f}" for f in FILTER_ARGS])
    def test_test_filters(self, cmd: str) -> None:
        with create_main():
            args = setup_parser().parse_args(cmd.split(" "))
            code, result = testing.run(args)
            assert code == 0
            assert result == ""


@contextlib.contextmanager
def create_main():
    """Creates a main.py at the cwd if it does not exist."""
    main_path = Path(os.getcwd()) / "main.py"
    created_main = False

    if not os.path.exists(main_path):
        with open(main_path, "w") as f:
            created_main = True
            f.write("from pypanther import get_panther_rules, register; register(get_panther_rules())")

    try:
        yield
    finally:
        if created_main:
            os.remove(main_path)
