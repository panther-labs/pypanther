import argparse
import collections
import logging
import os
from typing import Optional, Tuple

from pypanther import cli_output, display
from pypanther.base import Rule, RuleTestResult
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules

INDENT = " " * 4


class TestResults:
    passed_rule_tests: dict[str, list[RuleTestResult]] = collections.defaultdict(list)
    """dict of rule ids to the tests that passed on the rule"""

    failed_rule_tests: dict[str, list[RuleTestResult]] = collections.defaultdict(list)
    """dict of rule ids to the tests that failed on the rule"""

    skipped_rules: list[str] = []
    """list of rule ids that had no tests"""

    def add_test_results(self, rule_id: str, results: list[RuleTestResult]) -> None:
        if len(results) == 0:
            self.skipped_rules.append(rule_id)

        for result in results:
            if result.passed:
                self.passed_rule_tests[rule_id].append(result)
            else:
                self.failed_rule_tests[rule_id].append(result)

    def total_passed(self) -> int:
        return sum([len(v) for _, v in self.passed_rule_tests.items()])

    def total_failed(self) -> int:
        return sum([len(v) for _, v in self.failed_rule_tests.items()])

    def total_skipped(self) -> int:
        return len(self.skipped_rules)

    def total_tests(self) -> int:
        return self.total_passed() + self.total_failed()

    def total_rules_tested(self) -> int:
        return len(self.passed_rule_tests) + len(self.failed_rule_tests) + len(self.skipped_rules)

    def had_failed_tests(self) -> bool:
        return len(self.failed_rule_tests) > 0


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    test_results = TestResults()

    for rule in registered_rules():
        results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        test_results.add_test_results(rule.id, results)

        if args.output == display.OUTPUT_TYPE_TEXT:
            print_rule_test_results(rule.id, results)

    match args.output:
        case display.OUTPUT_TYPE_JSON:
            pass
        case display.OUTPUT_TYPE_TEXT:
            print_failed_test_summary(test_results)
            print_test_summary(test_results)
        case _:
            return 1, f"Unsupported output: {args.output}"

    if test_results.had_failed_tests():
        return 1, ""

    return 0, ""


def print_rule_test_results(rule_id: str, results: list[RuleTestResult]) -> None:
    print(cli_output.header(rule_id) + ":")

    if len(results) == 0:
        print(INDENT, "SKIP:", "rule had no tests")

    for result in results:
        if result.passed:
            print(INDENT, cli_output.success("PASS") + ":", result.test.name)
        else:
            print(INDENT, cli_output.bold(cli_output.failed("FAIL")) + ":", result.test.name)

    print()  # new line


def print_failed_test_summary(test_results: TestResults) -> None:
    print(cli_output.header("Failed Tests") + ":")

    for i, failure in enumerate(test_results.failed_rule_tests.items(), start=1):
        rule_id, failed_tests = failure
        print(INDENT, str(i) + ".", cli_output.bold(rule_id) + ":")
        for failed_test in failed_tests:
            print(INDENT * 2, "-", failed_test.test.name)

    print()  # new line


def print_test_summary(test_results: TestResults) -> None:
    print(cli_output.header("Summary") + ":")
    print(INDENT, "Skipped rules:", "{:>3}".format(test_results.total_skipped()))
    print(INDENT, "Passed tests: ", "{:>3}".format(test_results.total_passed()))
    print(INDENT, "Failed tests: ", "{:>3}".format(test_results.total_failed()))
    print(INDENT, "Total tests:  ", "{:>3}".format(test_results.total_tests()))


def print_failed_test_results(
    failed_test_results: list[list[RuleTestResult]],
) -> None:
    if len(failed_test_results) == 0:
        return

    test_failure_separator: Optional[str] = None
    single_test_failure_separator: Optional[str] = None
    terminal_cols: Optional[int] = None
    try:
        terminal_cols = os.get_terminal_size().columns
        test_failure_separator = "=" * terminal_cols
        single_test_failure_separator = "-" * terminal_cols
    except OSError:
        pass

    if test_failure_separator:
        print(test_failure_separator)

    for failed_results in failed_test_results:
        if len(failed_results) == 0:
            continue

        if terminal_cols:
            side_count = int((terminal_cols - len(failed_results[0].rule_id)) / 2)
            print(f"{' ' * side_count}{failed_results[0].rule_id}{' ' * side_count}")

        for failed_result in failed_results:
            result = failed_result.detection_result
            test = failed_result.test

            if single_test_failure_separator:
                print(single_test_failure_separator)

            if result.detection_exception is not None:
                log_rule_func_exception(failed_result)

            aux_func_exceptions = {
                "title": result.title_exception,
                "description": result.description_exception,
                "reference": result.reference_exception,
                "severity": result.severity_exception,
                "runbook": result.runbook_exception,
                "destinations": result.destinations_exception,
                "dedup": result.dedup_exception,
                "alert_context": result.alert_context_exception,
            }

            had_aux_exc = False
            for method_name, exc in aux_func_exceptions.items():
                if exc:
                    had_aux_exc = True
                    log_aux_func_exception(failed_result, method_name, exc)

            if had_aux_exc:
                log_aux_func_failure(failed_result, aux_func_exceptions)

            if result.detection_exception is None and result.detection_output != test.expected_result:
                log_rule_test_failure(
                    failed_result,
                    "rule",
                    str(test.expected_result),
                    str(result.detection_output),
                )

            for func in [
                Rule.severity.__name__,
                Rule.title.__name__,
                Rule.description.__name__,
                Rule.runbook.__name__,
                Rule.alert_context.__name__,
                Rule.reference.__name__,
                Rule.dedup.__name__,
            ]:
                exc = getattr(result, f"{func}_exception")
                exp = getattr(test, f"expected_{func}")
                output = getattr(result, f"{func}_output")

                if exc is None and exp is not None and output != exp:
                    log_rule_test_failure(
                        failed_result,
                        func,
                        str(exp),
                        str(output) if str(output) != "" else "''",
                    )

        if test_failure_separator:
            print(test_failure_separator)


def log_rule_func_exception(failed_result: RuleTestResult) -> None:
    logging.error(
        "%s: Exception in test '%s' calling rule(): '%s': %s",
        failed_result.rule_id,
        failed_result.test.name,
        failed_result.detection_result.detection_exception,
        failed_result.test.location(),
        exc_info=failed_result.detection_result.detection_exception,
    )


def log_aux_func_exception(failed_result: RuleTestResult, method_name: str, exc: Exception) -> None:
    logging.warning(
        "%s: Exception in test '%s' calling %s()",
        failed_result.rule_id,
        failed_result.test.name,
        method_name,
        exc_info=exc,
    )


def log_rule_test_failure(failed_result: RuleTestResult, func: str, exp: str, output: str) -> None:
    logging.error(
        "%s: test '%s' returned the wrong result calling %s(), expected %s but got %s: %s",
        failed_result.rule_id,
        failed_result.test.name,
        func,
        exp,
        output,
        failed_result.test.location(),
    )


def log_aux_func_failure(failed_result: RuleTestResult, aux_func_exceptions: dict[str, Exception]) -> None:
    exc_msgs = [f"{name}()" for name, exc in aux_func_exceptions.items() if exc is not None]
    exc_msg = ", ".join(exc_msgs[:-1]) if len(exc_msgs) > 1 else exc_msgs[0]
    last_exc_msg = f" and {exc_msgs[-1]}" if len(exc_msgs) > 1 else ""

    logging.error(
        "%s: test '%s': %s%s raised an exception, see log output for stacktrace",
        failed_result.rule_id,
        failed_result.test.name,
        exc_msg,
        last_exc_msg,
    )
