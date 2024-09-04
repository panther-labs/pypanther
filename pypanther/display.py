import inspect
import json
from typing import Any, Callable, Dict, Type

from panther_core.enriched_event import PantherEvent
from prettytable import PrettyTable

from pypanther import utils
from pypanther.base import RULE_ALL_METHODS, Rule

DEFAULT_RULE_TABLE_ATTRS = [
    "id",
    "log_types",
    "default_severity",
    "enabled",
]

ALL_TABLE_ATTR = "all"
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
OUTPUT_TYPE_CSV = "csv"
DEFAULT_CLI_OUTPUT_TYPE = OUTPUT_TYPE_TEXT
COMMON_CLI_OUTPUT_TYPES = [
    OUTPUT_TYPE_TEXT,
    OUTPUT_TYPE_JSON,
]

JSON_INDENT_LEVEL = 2


def print_rule_table(rules: list[Type[Rule]], attributes: list[str] | None = None, print_total: bool = True) -> None:
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
        table.add_row(
            [rule_table_row_attr(rule, attr) for attr in attributes],
        )

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
    if print_total:
        print(f"Total rules: {len(rules)}")


def rule_table_row_attr(rule: Type[Rule], attr: str) -> str:
    val = getattr(rule, attr)

    if val == "" or val is None or val == []:
        return "-"

    if isinstance(val, list):
        return fmt_list_attr(val)

    return val


def fmt_list_attr(val: list) -> str:
    if len(val) > 2:
        val = val[:2] + [f"+{len(val) - 2}"]

    return ", ".join([str(s) for s in val])


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
    print(json.dumps({"rules": rule_dicts, "total_rules": len(rule_dicts)}, indent=JSON_INDENT_LEVEL))


def print_rules_as_csv(rules: list[Type[Rule]], attributes: list[str] | None = None) -> None:
    """
    Prints rules in CSV format for easy viewing and parsing.

    Parameters
    ----------
        rules (list[Type[Rule]]): The list of PantherRule subclasses that will be printed in CSV format.
        attributes (list[str] | None): The list of attributes that will appear as attributes in the CSV.
            Supplying None or an empty list will use defaults of [id, log_types, default_severity, enabled].

    """
    attributes = utils.dedup_list_preserving_order(attributes or [])
    check_rule_attributes(attributes)

    if len(attributes) == 0:
        attributes = DEFAULT_RULE_TABLE_ATTRS

    rule_dicts = [{attr: getattr(rule, attr) for attr in attributes} for rule in rules]

    # print the column labels as the header row
    print(",".join(attributes))

    # print the data rows
    for rule_dict in rule_dicts:
        print(",".join([attr_to_csv_fmt(rule_dict[k]) for k in rule_dict]))


def attr_to_csv_fmt(attr: Any) -> str:
    # take care of lists by quoting them
    if isinstance(attr, list):
        return f'"{",".join([str(val) for val in attr])}"'

    return str(attr)


def check_rule_attributes(attributes: list[str]) -> None:
    for attr in attributes or []:
        if attr not in VALID_RULE_TABLE_ATTRS:
            raise AttributeError(f"Attribute '{attr}' is not allowed.")


def _get_rule_dict_base(rule: Type[Rule]) -> Dict[str, Any]:
    rule_dict = rule.asdict()
    del rule_dict["tests"]
    rule_dict["include_filters"] = _prettify_filters(rule_dict["include_filters"])
    rule_dict["exclude_filters"] = _prettify_filters(rule_dict["exclude_filters"])
    for method in RULE_ALL_METHODS:
        method_attr = getattr(rule, method)
        try:
            rule_dict[method] = "\n" + inspect.getsource(method_attr)
        except BaseException:
            rule_dict[method] = repr(method_attr)
    return rule_dict


def _prettify_filters(filters: list[Callable[[PantherEvent], bool]]) -> list[str]:
    pretty_filters = []
    for filter_ in filters:
        pretty_filters.append(filter_.__name__)
    return pretty_filters


def print_rule_as_json(rule: Type[Rule], managed: bool) -> None:
    rule_dict = {}
    if managed:
        source = inspect.getsource(rule)
        rule_dict["class_definition"] = source
    else:
        rule_dict = _get_rule_dict_base(rule)
    rule_json = json.dumps(rule_dict, indent=JSON_INDENT_LEVEL)
    print(rule_json)


def print_rule_as_text(rule: Type[Rule], managed: bool) -> None:
    rule_text = ""
    if managed:
        rule_text = inspect.getsource(rule)
    else:
        rule_text = f"class {rule.__name__}:\n"
        rule_dict = _get_rule_dict_base(rule)
        for k, v in rule_dict.items():
            rule_text += f"    {k} = {v}\n"
    print(rule_text)
