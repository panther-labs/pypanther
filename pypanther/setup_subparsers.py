import argparse

from pypanther import display, get_rule, list_rules


def setup_list_rules_parser(list_rules_parser: argparse.ArgumentParser):
    list_rules_parser.set_defaults(func=list_rules.run)
    list_rules_parser.add_argument(
        "--managed",
        help="List panther managed rules",
        default=False,
        required=False,
        action="store_true",
    )
    list_rules_parser.add_argument(
        "--registered",
        help="List registered rules",
        default=False,
        required=False,
        action="store_true",
    )
    list_rules_parser.add_argument(
        "--log-types",
        help="Filter results by log types (i.e --log-types AWS.ALB Panther.Audit)",
        default=None,
        nargs="+",
        required=False,
    )
    list_rules_parser.add_argument(
        "--id",
        help="Filter results by id",
        type=str,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--create-alert",
        help="Filter results by create alert",
        type=bool,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--dedup-period-minutes",
        help="Filter results by dedup period minutes",
        type=int,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--display-name",
        help="Filter results by display name",
        type=str,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--enabled",
        help="Filter results by enabled status",
        type=bool,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--summary-attributes",
        help="Filter results by summary attributes (i.e --summary-attributes abc dce)",
        nargs="+",
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--threshold",
        help="Filter results by threshold",
        type=int,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--tags",
        help="Filter results by tags (e.g. --tags security prod)",
        nargs="+",
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--default-severity",
        help="Filter results by default severity",
        type=str,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--default-description",
        help="Filter results by default description",
        type=str,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--default-reference",
        help="Filter results by default reference",
        type=str,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--default-runbook",
        help="Filter results by default runbook",
        type=str,
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--default-destinations",
        help="Filter results by default destinations",
        nargs="+",
        default=None,
        required=False,
    )
    list_rules_parser.add_argument(
        "--attributes",
        help="Display attributes of rules as columns in printed table (i.e --attributes threshold default_display_name)",
        nargs="+",
        default=None,
        required=False,
        choices=display.VALID_RULE_TABLE_ATTRS,
    )
    list_rules_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.VALID_CLI_OUTPUT_TYPES,
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )


def setup_get_rule_parser(get_rules_parser: argparse.ArgumentParser):
    get_rules_parser.set_defaults(func=get_rule.run)
    get_rules_parser.add_argument(
        "--id",
        help="Required. The id of the Panther-managed item to get",
        required=True,
        type=str,
    )
    get_rules_parser.add_argument(
        "--output",
        help="The format to use for the output.",
        required=False,
        choices=display.VALID_CLI_OUTPUT_TYPES,
        default=display.DEFAULT_CLI_OUTPUT_TYPE,
    )
