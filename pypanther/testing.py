import argparse
import logging
import os
from typing import Optional, Tuple

from pypanther.base import PantherRuleTestResult
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    failed_test_results: list[list[PantherRuleTestResult]] = []
    for rule in registered_rules():
        results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        failures = [result for result in results if not result.Passed]
        if len(failures) > 0:
            failed_test_results.append(failures)

    print_failed_test_results(failed_test_results)

    if len(failed_test_results) > 0:
        return 1, "One or more rule tests are failing"

    return 0, "All tests passed"


def print_failed_test_results(
    failed_test_results: list[list[PantherRuleTestResult]],
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
            side_count = int((terminal_cols - len(failed_results[0].RuleID)) / 2)
            print(f"{' ' * side_count}{failed_results[0].RuleID}{' ' * side_count}")

        for failed_result in failed_results:
            if single_test_failure_separator:
                print(single_test_failure_separator)

            if failed_result.DetectionResult.detection_exception is not None:
                log_rule_func_exception(failed_result)

            aux_func_exceptions = {
                "title": failed_result.DetectionResult.title_exception,
                "description": failed_result.DetectionResult.description_exception,
                "reference": failed_result.DetectionResult.reference_exception,
                "severity": failed_result.DetectionResult.severity_exception,
                "runbook": failed_result.DetectionResult.runbook_exception,
                "destinations": failed_result.DetectionResult.destinations_exception,
                "dedup": failed_result.DetectionResult.dedup_exception,
                "alert_context": failed_result.DetectionResult.alert_context_exception,
            }

            had_aux_exc = False
            for method_name, exc in aux_func_exceptions.items():
                if exc:
                    had_aux_exc = True
                    log_aux_func_exception(failed_result, method_name, exc)

            if had_aux_exc:
                log_aux_func_failure(failed_result, aux_func_exceptions)

            if (
                failed_result.DetectionResult.detection_exception is None
                and failed_result.DetectionResult.detection_output != failed_result.Test.ExpectedResult
            ):
                log_rule_test_failure(failed_result)

        if test_failure_separator:
            print(test_failure_separator)


def log_rule_func_exception(failed_result: PantherRuleTestResult) -> None:
    logging.error(
        "%s: Exception in test '%s' calling rule(): '%s': %s",
        failed_result.RuleID,
        failed_result.Test.Name,
        failed_result.DetectionResult.detection_exception,
        failed_result.Test.location(),
        exc_info=failed_result.DetectionResult.detection_exception,
    )


def log_aux_func_exception(failed_result: PantherRuleTestResult, method_name: str, exc: Exception) -> None:
    logging.warning(
        "%s: Exception in test '%s' calling %s()",
        failed_result.RuleID,
        failed_result.Test.Name,
        method_name,
        exc_info=exc,
    )


def log_rule_test_failure(failed_result: PantherRuleTestResult) -> None:
    logging.error(
        "%s: test '%s' returned the wrong result, expected %s but got %s: %s",
        failed_result.RuleID,
        failed_result.Test.Name,
        failed_result.Test.ExpectedResult,
        failed_result.DetectionResult.detection_output,
        failed_result.Test.location(),
    )


def log_aux_func_failure(failed_result: PantherRuleTestResult, aux_func_exceptions: dict[str, Exception]) -> None:
    exc_msgs = [f"{name}()" for name, exc in aux_func_exceptions.items() if exc is not None]
    exc_msg = ", ".join(exc_msgs[:-1]) if len(exc_msgs) > 1 else exc_msgs[0]
    last_exc_msg = f" and {exc_msgs[-1]}" if len(exc_msgs) > 1 else ""

    logging.error(
        "%s: test '%s': %s%s raised an exception, see log output for stacktrace",
        failed_result.RuleID,
        failed_result.Test.Name,
        exc_msg,
        last_exc_msg,
    )
