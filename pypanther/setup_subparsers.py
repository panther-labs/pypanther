import argparse

from pypanther import display, get_rule, list_log_types, list_rules, shared_args, upload
from pypanther.vendor.panther_analysis_tool import util


def setup_list_rules_parser(list_rules_parser: argparse.ArgumentParser):
    list_rules_parser.set_defaults(func=list_rules.run)
    shared_args.for_filtering(list_rules_parser)
    list_rules_parser.add_argument(
        "--managed",
        help="List panther managed rules instead of registered rules to view available rules",
        default=False,
        required=False,
        action="store_true",
    )
    list_rules_parser.add_argument(
        "--attributes",
        help="Display attributes of rules as columns in printed table (i.e --attributes threshold default_display_name). "
        f"Use '{display.ALL_TABLE_ATTR}' to display all attributes.",
        nargs="+",
        default=display.DEFAULT_RULE_TABLE_ATTRS,
        required=False,
        choices=display.VALID_RULE_TABLE_ATTRS + [display.ALL_TABLE_ATTR],
    )
    list_rules_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.COMMON_CLI_OUTPUT_TYPES + [display.OUTPUT_TYPE_CSV],
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )


def setup_get_rule_parser(get_rules_parser: argparse.ArgumentParser):
    get_rules_parser.set_defaults(func=get_rule.run)
    get_rules_parser.add_argument(
        "id",
        help="Required. The id of the rule to get",
        type=str,
    )
    get_rules_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.COMMON_CLI_OUTPUT_TYPES,
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )
    get_rules_parser.add_argument(
        "--class-definition",
        help="Include the original class definition in addition to the final versions of the attributes",
        required=False,
        default=False,
        action="store_true",
    )


def setup_test_parser(test_parser: argparse.ArgumentParser):
    shared_args.for_filtering(test_parser)
    test_parser.add_argument(
        "--test-names",
        help="The names of the tests to run, space delimited. If not specified, all tests on filtered items will be run",
        nargs="+",
        default=None,
        required=False,
    )
    test_parser.add_argument(
        "--verbose",
        help="Verbose output, includes passing tests, skipped tests, and exception stack traces",
        default=False,
        required=False,
        action="store_true",
    )
    test_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.COMMON_CLI_OUTPUT_TYPES,
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )


def setup_upload_parser(upload_parser: argparse.ArgumentParser):
    upload_parser.set_defaults(func=util.func_with_backend(upload.run))
    upload_parser.add_argument(
        "--max-retries",
        help="Retry to upload on a failure for a maximum number of times",
        default=10,
        type=int,
        required=False,
    )
    upload_parser.add_argument(
        "--skip-tests",
        help="Skip running tests and go directly to upload",
        default=False,
        required=False,
        action="store_true",
    )
    upload_parser.add_argument(
        "--confirm",
        help="Proceed with the upload without requiring user input",
        default=False,
        required=False,
        action="store_true",
    )
    upload_parser.add_argument(
        "--verbose",
        help="Verbose output",
        default=False,
        required=False,
        action="store_true",
    )
    upload_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.COMMON_CLI_OUTPUT_TYPES,
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )


def setup_list_log_types_parser(list_log_types_parser: argparse.ArgumentParser):
    list_log_types_parser.set_defaults(func=list_log_types.run)
    list_log_types_parser.add_argument(
        "substring",
        nargs="?",
        help="Filter log types by a substring. Only log types that include the substring will be printed.",
    )
    list_log_types_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.COMMON_CLI_OUTPUT_TYPES,
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )
