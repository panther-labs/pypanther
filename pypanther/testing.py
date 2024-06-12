import argparse
import logging
import os
from typing import Tuple

from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    for rule in registered_rules():
        rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)

    logging.info("All tests passed")
    return 0, ""
