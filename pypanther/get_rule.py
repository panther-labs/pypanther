import argparse
import os
from typing import Tuple

from pypanther import display
from pypanther.get import get_panther_rules
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        return 1, "No main.py found."
    found_rules = set(get_panther_rules(id=args.id)).union(registered_rules(id=args.id))
    if len(found_rules) == 0:
        return 1, f"Found no rules matching id={args.id}"
    if len(found_rules) > 1:
        return 1, f"Found multiple rules matching id={args.id}"
    rule = found_rules.pop()

    try:
        match args.output:
            case display.OUTPUT_TYPE_TEXT:
                display.print_rule_as_text(rule, args.original)
            case display.OUTPUT_TYPE_JSON:
                display.print_rule_as_json(rule, args.original)
            case _:
                return 1, f"Unsupported output: {args.output}"
    except OSError as e:
        return 1, f"Error getting details for rule {args.id}: {e!r}"

    return 0, ""
