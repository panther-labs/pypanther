import argparse


def for_filtering(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-types",
        help="Filter by log types (i.e --log-types AWS.ALB Panther.Audit)",
        default=None,
        nargs="+",
        required=False,
    )
    parser.add_argument(
        "--id",
        help="Filter by id",
        type=str,
        default=None,
        required=False,
    )

    create_alert_group = parser.add_mutually_exclusive_group()

    create_alert_group.add_argument(
        "--create-alert",
        help="Filter by items that create alerts",
        default=None,
        action="store_true",
    )

    create_alert_group.add_argument(
        "--no-create-alert",
        help="Filter by items that don't create alerts",
        dest="create_alert",
        action="store_false",
    )
    parser.add_argument(
        "--dedup-period-minutes",
        help="Filter by dedup period minutes",
        type=int,
        default=None,
        required=False,
    )
    parser.add_argument(
        "--display-name",
        help="Filter by display name",
        type=str,
        default=None,
        required=False,
    )
    enable_disable_group = parser.add_mutually_exclusive_group()

    enable_disable_group.add_argument(
        "--enabled",
        help="Filter only on enabled items",
        default=None,
        action="store_true",
    )
    enable_disable_group.add_argument(
        "--disabled",
        help="Filter only on disabled items",
        dest="enabled",
        action="store_false",
    )
    parser.add_argument(
        "--summary-attributes",
        help="Filter by summary attributes (i.e --summary-attributes abc dce)",
        nargs="+",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--threshold",
        help="Filter by threshold",
        type=int,
        default=None,
        required=False,
    )
    parser.add_argument(
        "--tags",
        help="Filter by tags (e.g. --tags security prod)",
        nargs="+",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--default-severity",
        help="Filter by default severity",
        type=str,
        default=None,
        required=False,
    )
    parser.add_argument(
        "--default-description",
        help="Filter by default description",
        type=str,
        default=None,
        required=False,
    )
    parser.add_argument(
        "--default-reference",
        help="Filter by default reference",
        type=str,
        default=None,
        required=False,
    )
    parser.add_argument(
        "--default-runbook",
        help="Filter by default runbook",
        type=str,
        default=None,
        required=False,
    )
    parser.add_argument(
        "--default-destinations",
        help="Filter by default destinations",
        nargs="+",
        default=None,
        required=False,
    )
