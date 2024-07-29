import argparse
from typing import Tuple

from pypanther import display
from pypanther.get import get_panther_rules


def run(args: argparse.Namespace) -> Tuple[int, str]:
    found_rules = get_panther_rules(id=args.id)
    if len(found_rules) == 0:
        return 1, f"Found no rules matching id={args.id}"
    if len(found_rules) > 1:
        return 1, f"Found multiple rules matching id={args.id}"
    rule = found_rules[0]

    try:
        match args.output:
            case "text":
                display.print_rule_as_text(rule)
            case "json":
                display.print_rule_as_json(rule)
            case _:
                return 1, f"Unsupported output: {args.output}"
    except OSError as e:
        return 1, f"Error getting details for rule {args.id}: {repr(e)}"

    return 0, ""
