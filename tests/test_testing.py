from panther_core import PantherEvent

from pypanther import testing
from pypanther.base import Rule, RuleTest, Severity
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.log_types import LogType
from pypanther.main import setup_parser

get_data_model = DATA_MODEL_CACHE.data_model_of_logtype


class Test(Rule):
    id = "Test"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.LOW

    def rule(self, event: PantherEvent) -> bool:
        return False

    def alert_context(self, event: PantherEvent) -> dict:
        return {"hi": "bye"}


class TestPrintRuleTestResults:
    def test_no_tests(self, capsys) -> None:
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        std = capsys.readouterr()
        assert std.out == ""
        assert std.err == ""

    def test_all_pass(self, capsys) -> None:
        Test.tests = [RuleTest(name="test", expected_result=False, log={})]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        std = capsys.readouterr()
        assert std.out == ""
        assert std.err == ""

    def test_rule_func_failure(self, capsys) -> None:
        Test.tests = [RuleTest(name="test", expected_result=True, log={})]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

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
        Test.tests = [RuleTest(name="test", expected_severity=Severity.HIGH, expected_result=False, log={})]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

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
        Test.tests = [RuleTest(name="test", expected_alert_context={"sad": "time"}, expected_result=False, log={})]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

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
        Test.tests = [
            RuleTest(
                name="test",
                expected_alert_context={"sad": "time"},
                expected_severity=Severity.HIGH,
                expected_result=True,
                log={},
            )
        ]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "     - Expected severity() to return 'HIGH', but got 'LOW'\n"
            "     - Expected alert_context() to return '{'sad': 'time'}', but got '{\"hi\": \"bye\"}'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    # TODO: Fix this to test exceptions regular and verbose
    # def test_exceptions(self, capsys) -> None:
    #     class Sub(Test):
    #         def severity(self, event: PantherEvent) -> SeverityType:
    #             assert 1 == 0
    #
    #         def alert_context(self, event: PantherEvent) -> dict:
    #             assert 1 == 0, "msg"
    #
    #     Sub.tests = [RuleTest(name="test", expected_result=False, log={})]
    #     args = setup_parser().parse_args("test".split(" "))
    #     testing.print_rule_test_results(args, Sub.id, Sub.run_tests(get_data_model))
    #
    #     exp = (
    #         "\x1b[95mTest\x1b[0m:\n"
    #         "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
    #         "     - Exception occurred in severity()\n"
    #         "     - Exception occurred in alert_context(): msg\n"
    #         "\n"
    #     )
    #     std = capsys.readouterr()
    #     assert std.out == exp
    #     assert std.err == ""

    def test_many_tests(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test1", expected_result=True, log={}),
            RuleTest(name="test2", expected_result=False, expected_title="bad", log={}),
        ]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test1\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test2\n"
            "     - Expected title() to return 'bad', but got 'Test'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_both_pass_and_fail(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test", expected_result=True, log={}),
            RuleTest(name="test", expected_result=False, log={}),
        ]
        args = setup_parser().parse_args("test".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_both_pass_and_fail_verbose(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test", expected_result=True, log={}),
            RuleTest(name="test", expected_result=False, log={}),
        ]
        args = setup_parser().parse_args("test --verbose".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        exp = (
            "\x1b[95mTest\x1b[0m:\n"
            "   \x1b[1m\x1b[91mFAIL\x1b[0m\x1b[0m: test\n"
            "     - Expected rule() to return 'True', but got 'False'\n"
            "   \x1b[92mPASS\x1b[0m: test\n"
            "\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_no_tests_verbose(self, capsys) -> None:
        Test.tests = []
        args = setup_parser().parse_args("test --verbose".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        exp = "\x1b[95mTest\x1b[0m:\n   SKIP: rule had no tests\n\n"
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_pass_tests_verbose(self, capsys) -> None:
        Test.tests = [
            RuleTest(name="test1", expected_result=False, log={}),
            RuleTest(name="test2", expected_result=False, log={}),
        ]
        args = setup_parser().parse_args("test --verbose".split(" "))
        testing.print_rule_test_results(args, Test.id, Test.run_tests(get_data_model))

        exp = "\x1b[95mTest\x1b[0m:\n   \x1b[92mPASS\x1b[0m: test1\n   \x1b[92mPASS\x1b[0m: test2\n" "\n"
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""


class TestPrintFailureSummary:
    def test_no_tests(self, capsys) -> None:
        Test.tests = []
        test_results = testing.TestResults()
        test_results.add_test_results(Test.id, Test.run_tests(get_data_model))
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
        test_results.add_test_results(Test.id, Test.run_tests(get_data_model))
        testing.print_failed_test_summary(test_results)

        exp = ""
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""

    def test_some_failures(self, capsys) -> None:
        Test.tests = []

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

        test_results = testing.TestResults()
        test_results.add_test_results(Test.id, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1.id, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2.id, Sub2.run_tests(get_data_model))
        testing.print_failed_test_summary(test_results)

        exp = (
            "\x1b[95mFailed Tests\x1b[0m:\n"
            "   1. \x1b[1mSub1\x1b[0m:\n"
            "     - test1\n"
            "     - test3\n"
            "   2. \x1b[1mSub2\x1b[0m:\n"
            "     - test4\n"
            "     - test6\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""


class TestPrintTestSummary:
    def test_no_tests(self, capsys) -> None:
        Test.tests = []
        test_results = testing.TestResults()
        test_results.add_test_results(Test.id, Test.run_tests(get_data_model))
        testing.print_test_summary(test_results)

        exp = (
            "\x1b[95mSummary\x1b[0m:\n"
            "   Skipped rules:   1\n"
            "   Passed rules:    0\n"
            "   \x1b[4mFailed rules:    0\x1b[0m\n"
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
        test_results.add_test_results(Test.id, Test.run_tests(get_data_model))
        testing.print_test_summary(test_results)

        exp = (
            "\x1b[95mSummary\x1b[0m:\n"
            "   Skipped rules:   0\n"
            "   Passed rules:    1\n"
            "   \x1b[4mFailed rules:    0\x1b[0m\n"
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

        test_results = testing.TestResults()
        test_results.add_test_results(Test.id, Test.run_tests(get_data_model))
        test_results.add_test_results(Sub1.id, Sub1.run_tests(get_data_model))
        test_results.add_test_results(Sub2.id, Sub2.run_tests(get_data_model))
        testing.print_test_summary(test_results)

        exp = (
            "\x1b[95mSummary\x1b[0m:\n"
            "   Skipped rules:   1\n"
            "   Passed rules:    0\n"
            "   \x1b[4mFailed rules:    2\x1b[0m\n"
            "   Total rules:     3\n"
            "\n"
            "   Passed tests:    2\n"
            "   \x1b[4mFailed tests:    4\x1b[0m\n"
            "   Total tests:     6\n"
        )
        std = capsys.readouterr()
        assert std.out == exp
        assert std.err == ""
