import argparse
import os
from typing import Tuple

from pypanther.display import print_rule_table, print_rules_as_json
from pypanther.get import get_panther_rules
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    rules = set()

    if not args.registered and not args.managed:
        return 1, "At least one of --registered or --managed is required"

    if args.registered:
        try:
            import_main(os.getcwd(), "main")
        except NoMainModuleError:
            return 1, "No main.py found. Cannot use --registered option without main.py."
        rules = registered_rules(
            log_types=args.log_types,
            id=args.id,
            create_alert=args.create_alert,
            dedup_period_minutes=args.dedup_period_minutes,
            display_name=args.display_name,
            enabled=args.enabled,
            summary_attributes=args.summary_attributes,
            threshold=args.threshold,
            tags=args.tags,
            default_severity=args.default_severity,
            default_description=args.default_description,
            default_reference=args.default_reference,
            default_runbook=args.default_runbook,
            default_destinations=args.default_destinations,
        )

    if args.managed:
        panther_rules = get_panther_rules(
            log_types=args.log_types,
            id=args.id,
            create_alert=args.create_alert,
            dedup_period_minutes=args.dedup_period_minutes,
            display_name=args.display_name,
            enabled=args.enabled,
            summary_attributes=args.summary_attributes,
            threshold=args.threshold,
            tags=args.tags,
            default_severity=args.default_severity,
            default_description=args.default_description,
            default_reference=args.default_reference,
            default_runbook=args.default_runbook,
            default_destinations=args.default_destinations,
        )
        for rule in panther_rules:
            rules.add(rule)

    try:
        match args.output:
            case "text":
                print_rule_table(list(rules), args.attributes)
            case "json":
                print_rules_as_json(list(rules), args.attributes)
            case _:
                return 1, f"Unsupported output: {args.output}"
    except AttributeError as err:
        return 1, f"Invalid attribute was given in --attributes option: {str(err)}"

    return 0, ""
