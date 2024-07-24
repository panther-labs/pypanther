import json
from typing import Type

from prettytable import PrettyTable

from pypanther.base import Rule


def print_rule_table(rules: list[Type[Rule]], attributes: list[str] | None = None) -> None:
    """Prints rules in a table format for easy viewing.

    Parameters:
        rules (list[Type[Rule]]): The list of PantherRule subclasses that will be printed in table format.
        attributes (list[str] | None): The list of attributes that will appear as columns in the table.
            Supplying None or an empty list will use defaults of [id, log_types, default_severity, enabled, create_alert].
    """
    check_rule_attributes(rules, attributes)

    if attributes is None or len(attributes) == 0:
        attributes = [
            "id",
            "log_types",
            "default_severity",
            "enabled",
            "create_alert",
        ]

    table = PrettyTable()
    table.field_names = attributes

    for rule in rules:
        table.add_row([getattr(rule, attr) if attr != "log_types" else fmt_log_types_attr(rule) for attr in attributes])

    if "id" in attributes:
        table.sortby = "id"
    else:
        table.sortby = attributes[0]

    print(table)


def fmt_log_types_attr(rule: Type[Rule]) -> str:
    log_types = rule.log_types
    if len(log_types) > 2:
        log_types = log_types[:2] + ["+{}".format(len(log_types) - 2)]

    return ", ".join([str(s) for s in log_types])


def print_rules_as_json(rules: list[Type[Rule]], attributes: list[str] | None = None) -> None:
    """Prints rules in JSON format for easy viewing.

    Parameters:
        rules (list[Type[Rule]]): The list of PantherRule subclasses that will be printed in JSON format.
        attributes (list[str] | None): The list of attributes that will appear as attributes in the JSON.
            Supplying None or an empty list will use defaults of [id, log_types, default_severity, enabled, create_alert].
    """
    check_rule_attributes(rules, attributes)

    if attributes is None or len(attributes) == 0:
        attributes = [
            "id",
            "log_types",
            "default_severity",
            "enabled",
            "create_alert",
        ]

    rule_dicts = [{attr: getattr(rule, attr) for attr in attributes} for rule in rules]
    print(json.dumps(rule_dicts, indent=2))


def check_rule_attributes(rules: list[Type[Rule]], attributes: list[str] | None = None) -> None:
    for attr in attributes or []:
        for rule in rules:
            if not hasattr(rule, attr):
                raise AttributeError(f"Attribute '{attr}' does not exist on rule {rule.__name__}")
