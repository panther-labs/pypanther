import argparse
import collections
import json
import logging
import os
import traceback
from typing import Any, Tuple

from pypanther import cli_output, display
from pypanther.base import Rule, RuleTestResult
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules

INDENT = " " * 2


class TestResults:
    passed_rule_tests: dict[str, list[RuleTestResult]]
    """dict of rule ids to the tests that passed on the rule"""

    failed_rule_tests: dict[str, list[RuleTestResult]]
    """dict of rule ids to the tests that failed on the rule"""

    skipped_rules: list[str] = []
    """list of rule ids that had no tests"""

    def __init__(self):
        self.passed_rule_tests = collections.defaultdict(list)
        self.failed_rule_tests = collections.defaultdict(list)
        self.skipped_rules = []

    def add_test_results(self, rule_id: str, results: list[RuleTestResult]) -> None:
        if len(results) == 0:
            self.skipped_rules.append(rule_id)

        for result in results:
            if result.passed:
                self.passed_rule_tests[rule_id].append(result)
            else:
                self.failed_rule_tests[rule_id].append(result)

    def num_passed_tests(self) -> int:
        return sum([len(v) for _, v in self.passed_rule_tests.items()])

    def num_failed_tests(self) -> int:
        return sum([len(v) for _, v in self.failed_rule_tests.items()])

    def num_skipped_rules(self) -> int:
        return len(self.skipped_rules)

    def total_tests(self) -> int:
        return self.num_passed_tests() + self.num_failed_tests()

    def had_failed_tests(self) -> bool:
        return len(self.failed_rule_tests) > 0

    def total_rules(self) -> int:
        return len(
            {k for k in list(self.failed_rule_tests.keys()) + list(self.passed_rule_tests.keys()) + self.skipped_rules}
        )

    def num_passed_rules(self) -> int:
        return len({k for k in self.passed_rule_tests if k not in self.failed_rule_tests})

    def num_failed_rules(self) -> int:
        return len(self.failed_rule_tests)

    def all_rule_tests(self) -> dict[str, list[RuleTestResult]]:
        rule_test_results = collections.defaultdict(list)

        for rule_id, tests in self.passed_rule_tests.items():
            rule_test_results[rule_id].extend(tests)
        for rule_id, tests in self.failed_rule_tests.items():
            rule_test_results[rule_id].extend(tests)
        for rule_id in self.skipped_rules:
            rule_test_results[rule_id] = []

        return rule_test_results


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    test_results = run_tests(args)

    if args.output == display.OUTPUT_TYPE_JSON:
        print(
            json.dumps(
                test_output_dict(test_results, args.verbose),
                indent=display.JSON_INDENT_LEVEL,
            )
        )

    if test_results.had_failed_tests():
        return 1, ""

    return 0, ""


def run_tests(args: argparse.Namespace) -> TestResults:
    test_results = TestResults()

    for rule in registered_rules(
        log_types=args.log_types if hasattr(args, "log_types") else None,
        id=args.id if hasattr(args, "id") else None,
        create_alert=args.create_alert if hasattr(args, "create_alert") else None,
        dedup_period_minutes=args.dedup_period_minutes if hasattr(args, "dedup_period_minutes") else None,
        display_name=args.display_name if hasattr(args, "display_name") else None,
        enabled=args.enabled if hasattr(args, "enabled") else None,
        summary_attributes=args.summary_attributes if hasattr(args, "summary_attributes") else None,
        threshold=args.threshold if hasattr(args, "threshold") else None,
        tags=args.tags if hasattr(args, "tags") else None,
        default_severity=args.default_severity if hasattr(args, "default_severity") else None,
        default_description=args.default_description if hasattr(args, "default_description") else None,
        default_reference=args.default_reference if hasattr(args, "default_reference") else None,
        default_runbook=args.default_runbook if hasattr(args, "default_runbook") else None,
        default_destinations=args.default_destinations if hasattr(args, "default_destinations") else None,
    ):
        results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        test_results.add_test_results(rule.id, results)

        if args.output == display.OUTPUT_TYPE_TEXT:
            # intent here is to give the user more interactive feedback by printing
            # the tests as they are running instead of waiting until the very end.
            print_rule_test_results(args.verbose, rule.id, results)

    if args.output == display.OUTPUT_TYPE_TEXT:
        print_failed_test_summary(test_results)
        print_test_summary(test_results)

    return test_results


def test_output_dict(test_results: TestResults, verbose: bool) -> dict:
    return {
        "test_results": get_test_results_as_dict(test_results, verbose),
        "failed_tests_summary": get_failed_test_summary_as_dict(test_results),
        "test_summary": get_test_summary_as_dict(test_results),
    }


def get_test_results_as_dict(test_results: TestResults, verbose: bool) -> dict[str, Any]:
    test_results_dict = {
        rule_id: [
            {
                "test_name": result.test.name,
                "passed": result.passed,
                "exceptions": [
                    {
                        "func": func,
                        "exception": str(exc),
                        "stacktrace": "".join(traceback.format_exception(exc)),
                    }
                    for func, exc in get_rule_exceptions(result).items()
                    if exc is not None
                ],
                "failed_results": [
                    {
                        "func": func,
                        "expected": exp,
                        "output": exp,
                        "matched": match,
                    }
                    for func, exp, out, match in get_rule_results(result)
                    if not match and exp is not None
                ],
            }
            for result in results
        ]
        for rule_id, results in test_results.all_rule_tests().items()
    }

    if not verbose:
        # remove passing test results
        test_results_dict = {
            rule_id: [result for result in results if not result["passed"]]
            for rule_id, results in test_results_dict.items()
        }
        # prune empty lists because all tests passed or had no tests
        test_results_dict = {rule_id: results for rule_id, results in test_results_dict.items() if len(results) > 0}
        # remove stacktraces from exceptions
        for _, results in test_results_dict.items():
            for result in results:
                for exc_dict in result["exceptions"]:  # type: ignore
                    del exc_dict["stacktrace"]

    return test_results_dict


def get_failed_test_summary_as_dict(test_results: TestResults) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": rule_id,
            "num_failed_tests": len(failed_tests),
            "failed_tests": [failed_test.test.name for failed_test in failed_tests],
        }
        for rule_id, failed_tests in test_results.failed_rule_tests.items()
    ]


def get_test_summary_as_dict(test_results: TestResults) -> dict[str, Any]:
    return {
        "skipped_rules": test_results.num_skipped_rules(),
        "passed_rules": test_results.num_passed_rules(),
        "failed_rules": test_results.num_failed_rules(),
        "total_rules": test_results.total_rules(),
        "passed_tests": test_results.num_passed_tests(),
        "failed_tests": test_results.num_failed_tests(),
        "total_tests": test_results.total_tests(),
    }


def print_rule_test_results(verbose: bool, rule_id: str, results: list[RuleTestResult]) -> None:
    if verbose or any(not result.passed for result in results):
        print(cli_output.header(rule_id) + ":")

    if len(results) == 0 and verbose:
        print(INDENT, "SKIP:", "rule had no tests")

    for result in results:
        if result.passed and verbose:
            print(INDENT, cli_output.success("PASS") + ":", result.test.name)

        elif not result.passed:
            print(INDENT, cli_output.bold(cli_output.failed("FAIL")) + ":", result.test.name)

            exceptions = get_rule_exceptions(result)
            for func, exc in exceptions.items():
                if exc is not None:
                    print(INDENT * 2, "-", f"Exception occurred in {func}(){': ' + str(exc) if str(exc) else ''}")
                    if verbose:
                        print_failed_test_exception(exc)

            for func, exp, out, match in get_rule_results(result):
                if exp is not None and exceptions.get(func, None) is None and not match:
                    print(INDENT * 2, "-", f"Expected {func}() to return '{exp}', but got '{out}'")

    if verbose or any(not result.passed for result in results):
        print()  # new line


def print_failed_test_exception(exc: Exception) -> None:
    print()  # new line
    for multi_line in traceback.format_exception(exc):
        for line in multi_line.split("\n"):
            if len(line) > 0:
                print(INDENT * 6, cli_output.failed(line))
    print()  # new line


def print_failed_test_summary(test_results: TestResults) -> None:
    if not test_results.had_failed_tests():
        return

    print(cli_output.header("Failed Tests") + ":")

    for i, failure in enumerate(test_results.failed_rule_tests.items(), start=1):
        rule_id, failed_tests = failure
        print(INDENT, str(i) + ".", cli_output.bold(rule_id) + ":")

        for failed_test in failed_tests:
            print(INDENT * 2, "-", failed_test.test.name)

    print()  # new line


def print_test_summary(test_results: TestResults) -> None:
    print(cli_output.header("Test Summary") + ":")

    print(INDENT, "Skipped rules: {:>3}".format(test_results.num_skipped_rules()))
    print(INDENT, "Passed rules:  {:>3}".format(test_results.num_passed_rules()))
    print(INDENT, cli_output.underline("Failed rules:  {:>3}".format(test_results.num_failed_rules())))
    print(INDENT, "Total rules:   {:>3}".format(test_results.total_rules()))
    print()  # new line

    print(INDENT, "Passed tests:  {:>3}".format(test_results.num_passed_tests()))
    print(INDENT, cli_output.underline("Failed tests:  {:>3}".format(test_results.num_failed_tests())))
    print(INDENT, "Total tests:   {:>3}".format(test_results.total_tests()))


def get_rule_exceptions(result: RuleTestResult) -> dict[str, Exception]:
    return {
        "rule": result.detection_result.detection_exception,
        Rule.title.__name__: result.detection_result.title_exception,
        Rule.description.__name__: result.detection_result.description_exception,
        Rule.reference.__name__: result.detection_result.reference_exception,
        Rule.severity.__name__: result.detection_result.severity_exception,
        Rule.runbook.__name__: result.detection_result.runbook_exception,
        Rule.destinations.__name__: result.detection_result.destinations_exception,
        Rule.dedup.__name__: result.detection_result.dedup_exception,
        Rule.alert_context.__name__: result.detection_result.alert_context_exception,
    }


def get_rule_results(result: RuleTestResult) -> list[Tuple[str, Any, Any, bool]]:
    t = result.test
    r = result.detection_result
    return [
        ("rule", t.expected_result, r.detection_output, t.expected_result == r.detection_output),
        (Rule.title.__name__, t.expected_title, r.title_output, t.expected_title == r.title_output),
        (
            Rule.description.__name__,
            t.expected_description,
            r.description_output,
            t.expected_description == r.description_output,
        ),
        (Rule.reference.__name__, t.expected_reference, r.reference_output, t.expected_reference == r.reference_output),
        (Rule.severity.__name__, t.expected_severity, r.severity_output, t.expected_severity == r.severity_output),
        (Rule.runbook.__name__, t.expected_runbook, r.runbook_output, t.expected_runbook == r.runbook_output),
        (Rule.dedup.__name__, t.expected_dedup, r.dedup_output, t.expected_dedup == r.dedup_output),
        (
            Rule.alert_context.__name__,
            t.expected_alert_context,
            r.alert_context_output,
            t.expected_alert_context == json.loads(r.alert_context_output),
        ),
    ]


def print_test_results_json(test_results: TestResults) -> None:
    print()
