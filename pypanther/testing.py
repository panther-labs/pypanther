import argparse
import logging
import os
from typing import Tuple

from pypanther.base import PantherRuleTestFailure
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    test_failure_separator = "-" * os.get_terminal_size().columns

    test_failed = False
    for rule in registered_rules():
        try:
            rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
        except PantherRuleTestFailure:
            test_failed = True
            print(test_failure_separator)

    if test_failed:
        return 1, "One or more rule tests are failing"

    return 0, "All tests passed"
