import argparse
import logging
import os
from typing import Tuple

from pypanther import registered_rules
from pypanther.get import print_rule_table, get_panther_rules
from pypanther.import_main import NoMainModuleError, import_main


def run(args: argparse.Namespace) -> Tuple[int, str]:
    print(args)
    rules = []

    if not args.registered and not args.managed:
        logging.error("--registered or --managed is required")
        return 1, ""

    if args.registered:
        try:
            import_main(os.getcwd(), "main")
        except NoMainModuleError:
            logging.error("No main.py found")
            return 1, ""
        rules = list(registered_rules())

    if args.managed:
        rules.extend(
            get_panther_rules(
                log_types=args.log_types,
                id=args.id,
                create_alert=args.create_alert,
                dedup_period_minutes=args.dedup_period_minutes,
                display_name=args.display_name,
                enabled=args.enabled,
                summary_attributes=args.summary_attributes,
                threshold=args.threshold,
                tags=args.tags,
                default_severity=args.default_severity.upper()
                if type(args.default_severity) == str
                else args.default_severity,
                default_description=args.default_description,
                default_reference=args.default_reference,
                default_runbook=args.default_runbook,
                default_destinations=args.default_destinations,
            )
        )

    print_rule_table(rules)
    return 0, ""
