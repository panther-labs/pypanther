import argparse
import os
from typing import Tuple

from pypanther import display
from pypanther.get import get_panther_rules
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    rules = set()

    if len(args.attributes) > 1 and display.ALL_TABLE_ATTR in args.attributes:
        return 1, f"Cannot use any other attributes with '{display.ALL_TABLE_ATTR}'."

    if display.ALL_TABLE_ATTR in args.attributes:
        args.attributes = display.VALID_RULE_TABLE_ATTRS

    if not args.managed:
        try:
            import_main(os.getcwd(), "main")
        except NoMainModuleError:
            return 1, "No main.py found. Cannot list registered rules without main.py."
        rules = registered_rules(
            log_types=getattr(args, "log_types", None),
            id=getattr(args, "id", None),
            create_alert=getattr(args, "create_alert", None),
            dedup_period_minutes=getattr(args, "dedup_period_minutes", None),
            display_name=getattr(args, "display_name", None),
            enabled=getattr(args, "enabled", None),
            summary_attributes=getattr(args, "summary_attributes", None),
            threshold=getattr(args, "threshold", None),
            tags=getattr(args, "tags", None),
            default_severity=getattr(args, "default_severity", None),
            default_description=getattr(args, "default_description", None),
            default_reference=getattr(args, "default_reference", None),
            default_runbook=getattr(args, "default_runbook", None),
            default_destinations=getattr(args, "default_destinations", None),
        )

    if args.managed:
        panther_rules = get_panther_rules(
            log_types=getattr(args, "log_types", None),
            id=getattr(args, "id", None),
            create_alert=getattr(args, "create_alert", None),
            dedup_period_minutes=getattr(args, "dedup_period_minutes", None),
            display_name=getattr(args, "display_name", None),
            enabled=getattr(args, "enabled", None),
            summary_attributes=getattr(args, "summary_attributes", None),
            threshold=getattr(args, "threshold", None),
            tags=getattr(args, "tags", None),
            default_severity=getattr(args, "default_severity", None),
            default_description=getattr(args, "default_description", None),
            default_reference=getattr(args, "default_reference", None),
            default_runbook=getattr(args, "default_runbook", None),
            default_destinations=getattr(args, "default_destinations", None),
        )
        for rule in panther_rules:
            rules.add(rule)

    try:
        match args.output:
            case "text":
                display.print_rule_table(list(rules), attributes=args.attributes, sort_by=args.sort_by)
            case "json":
                display.print_rules_as_json(list(rules), attributes=args.attributes, sort_by=args.sort_by)
            case "csv":
                display.print_rules_as_csv(list(rules), attributes=args.attributes, sort_by=args.sort_by)
            case _:
                return 1, f"Unsupported output: {args.output}"
    except AttributeError as err:
        return 1, f"Invalid attribute was given in --attributes option: {err!s}"

    return 0, ""
