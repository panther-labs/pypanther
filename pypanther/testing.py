import argparse
import logging
import os
from typing import Optional, Tuple

from pypanther.base import Rule, RuleTestResult
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    failed_test_results: list[list[RuleTestResult]] = []
    for rule in registered_rules():
        results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        failures = [result for result in results if not result.passed]
        if len(failures) > 0:
            failed_test_results.append(failures)

    print_failed_test_results(failed_test_results)

    if len(failed_test_results) > 0:
        return 1, "One or more rule tests are failing"

    return 0, "All tests passed"


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
