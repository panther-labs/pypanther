import inspect
import json
from typing import Any, Type

from prettytable import PrettyTable

from pypanther import utils
from pypanther.base import Rule

DEFAULT_RULE_TABLE_ATTRS = [
    "id",
    "log_types",
    "default_severity",
    "enabled",
]

VALID_RULE_TABLE_ATTRS = [
    *DEFAULT_RULE_TABLE_ATTRS,
    "create_alert",
    "dedup_period_minutes",
    "display_name",
    "summary_attributes",
    "threshold",
    "tags",
    "default_description",
    "default_reference",
    "default_runbook",
    "default_destinations",
]

OUTPUT_TYPE_JSON = "json"
OUTPUT_TYPE_TEXT = "text"
DEFAULT_CLI_OUTPUT_TYPE = OUTPUT_TYPE_TEXT
VALID_CLI_OUTPUT_TYPES = [
    OUTPUT_TYPE_TEXT,
    OUTPUT_TYPE_JSON,
]

JSON_INDENT_LEVEL = 2


def print_rule_table(rules: list[Type[Rule]], attributes: list[str] | None = None) -> None:
    """
    Prints rules in a table format for easy viewing.

    Parameters
    ----------
        rules (list[Type[Rule]]): The list of PantherRule subclasses that will be printed in table format.
        attributes (list[str] | None): The list of attributes that will appear as columns in the table.
            Supplying None or an empty list will use defaults of [id, log_types, default_severity, enabled].

    """
    attributes = utils.dedup_list_preserving_order(attributes or [])
    check_rule_attributes(attributes)

    if len(attributes) == 0:
        attributes = DEFAULT_RULE_TABLE_ATTRS

    table = PrettyTable()
    table.field_names = attributes

    for rule in rules:
        table.add_row([getattr(rule, attr) if attr != "log_types" else fmt_log_types_attr(rule) for attr in attributes])

    # sort the table by the first attr given or the ID
    # sortby must be set before setting sort_key
    table.sortby = "id" if "id" in attributes else (attributes or [])[0]

    # sort all columns in alphanumeric order by joining them
    def key(row: list[Any]) -> list[Any]:
        # row[0] is the sortby attr, row[1:] are all attrs in the row
        # for example: [id, id, log_type, enabled]
        # by replacing the [0] item we replace what it sorts by
        row[0] = "".join(str(val) for val in row[1:])
        return row

    table.sort_key = key

    print(table)


def fmt_log_types_attr(rule: Type[Rule]) -> str:
    log_types = rule.log_types
    if len(log_types) > 2:
        log_types = log_types[:2] + [f"+{len(log_types) - 2}"]

    return ", ".join([str(s) for s in log_types])


def print_rules_as_json(rules: list[Type[Rule]], attributes: list[str] | None = None) -> None:
    """
    Prints rules in JSON format for easy viewing.

    Parameters
    ----------
        rules (list[Type[Rule]]): The list of PantherRule subclasses that will be printed in JSON format.
        attributes (list[str] | None): The list of attributes that will appear as attributes in the JSON.
            Supplying None or an empty list will use defaults of [id, log_types, default_severity, enabled].

    """
    attributes = utils.dedup_list_preserving_order(attributes or [])
    check_rule_attributes(attributes)

    if len(attributes) == 0:
        attributes = DEFAULT_RULE_TABLE_ATTRS

    rule_dicts = [{attr: getattr(rule, attr) for attr in attributes} for rule in rules]
    print(json.dumps(rule_dicts, indent=JSON_INDENT_LEVEL))


def check_rule_attributes(attributes: list[str]) -> None:
    for attr in attributes or []:
        if attr not in VALID_RULE_TABLE_ATTRS:
            raise AttributeError(f"Attribute '{attr}' is not allowed.")


def print_rule_as_json(rule: Type[Rule]) -> None:
    source = inspect.getsource(rule)
    rule_dict = rule.asdict()
    del rule_dict["tests"]
    rule_dict["class_definition"] = source
    rule_json = json.dumps(rule_dict, indent=JSON_INDENT_LEVEL)
    print(rule_json)


def print_rule_as_text(rule: Type[Rule]) -> None:
    print(inspect.getsource(rule))
