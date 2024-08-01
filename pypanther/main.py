import argparse
import importlib
import logging
import sys
from typing import Callable, Tuple

from gql.transport.aiohttp import log as aiohttp_logger

from pypanther import testing
from pypanther.custom_logging import setup_logging
from pypanther.setup_subparsers import (
    setup_get_rule_parser,
    setup_list_rules_parser,
    setup_upload_parser,
    setup_test_parser,
)
from pypanther.vendor.panther_analysis_tool import util
from pypanther.vendor.panther_analysis_tool.command import standard_args
from pypanther.vendor.panther_analysis_tool.config import dynaconf_argparse_merge, setup_dynaconf


def run():
    setup_logging()

    parser = setup_parser()
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        aiohttp_logger.setLevel(logging.WARNING)

    config_file_settings = setup_dynaconf()
    dynaconf_argparse_merge(vars(args), config_file_settings)

    try:
        return_code, out = args.func(args)
    except util.BackendNotFoundException as err:
        logging.error('Backend not found: "%s"', err)
        return 1
    except Exception as err:  # pylint: disable=broad-except
        # Catch arbitrary exceptions without printing help message
        logging.warning('Unhandled exception: "%s"', err, exc_info=err, stack_info=True)
        logging.debug("Full error traceback:", exc_info=err)
        return 1

    if return_code > 0 and out:
        logging.error(out)
    elif return_code == 0 and out:
        logging.info(out)

    sys.exit(return_code)


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Command line tool for using Panther's Detections-as-Code V2.",
        prog="pypanther",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true", dest="debug")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Upload command
    upload_parser = subparsers.add_parser(
        "upload", help="Upload a file", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    standard_args.for_public_api(upload_parser, required=False)
    setup_upload_parser(upload_parser)

    # Test command
    test_parser = subparsers.add_parser(
        "test", help="run tests", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    test_parser.set_defaults(func=testing.run)
    setup_test_parser(test_parser)

    # Version command
    version_parser = subparsers.add_parser(
        "version", help="version", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    version_parser.set_defaults(func=version)

    # Get command
    get_parser = subparsers.add_parser(
        "get",
        help="Get the class associated with a specific id",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    get_parser.set_defaults(func=help_printer(get_parser))
    get_subparsers = get_parser.add_subparsers()
    get_rule_parser = get_subparsers.add_parser(
        name="rule",
        help="Get the class associated with a specific rule by id",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    setup_get_rule_parser(get_rule_parser)

    # List command
    list_parser = subparsers.add_parser(
        name="list", help="List managed or register content", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    list_parser.set_defaults(func=help_printer(list_parser))
    list_subparsers = list_parser.add_subparsers()
    list_rules_parser = list_subparsers.add_parser(
        name="rules",
        help="List panther managed and registered rules",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    setup_list_rules_parser(list_rules_parser)

    return parser


def help_printer(parser: argparse.ArgumentParser) -> Callable[[argparse.Namespace], Tuple[int, str]]:
    """
    A helper function for printing help messages. To be used as a commands func when you want the help message
    to be printed when it is run. Useful for when things have subcommands and running the top command is meaningless.
    """

    def wrapper(_: argparse.Namespace) -> Tuple[int, str]:
        parser.print_help()
        return 0, ""

    return wrapper


def version(args):
    print(importlib.metadata.version("pypanther"))
    return 0, ""


if __name__ == "__main__":
    run()
