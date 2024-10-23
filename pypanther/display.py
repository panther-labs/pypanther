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

DEFAULT_RULE_TABLE_SORT_BY = "id"

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


def print_rule_table(
    rules: list[Type[Rule]],
    attributes: list[str] | None = None,
    print_total: bool = True,
    sort_by: str | None = None,
) -> None:
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

    if not attributes:
        attributes = DEFAULT_RULE_TABLE_ATTRS

    if not sort_by or sort_by not in attributes:
        sort_by = "id" if "id" in attributes else attributes[0]

    rule_dicts = sorted(
        [{attr: getattr(rule, attr) for attr in attributes} for rule in rules],
        key=lambda d: d[sort_by],
    )

    table = PrettyTable(field_names=attributes)
    table.add_rows(
        [[pretty_format_text(value) for value in rule_dict.values()] for rule_dict in rule_dicts],
    )

    print(table)
    if print_total:
        print(f"Total rules: {len(rules)}")


def pretty_format_text(val) -> str:
    if val == "" or val is None or val == []:
        return "-"

    if isinstance(val, list):
        if len(val) > 2:
            val = val[:2] + [f"+{len(val) - 2}"]

        return ", ".join([str(s) for s in val])

    return val


def print_rules_as_json(
    rules: list[Type[Rule]],
    attributes: list[str] | None = None,
    sort_by: str | None = None,
) -> None:
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

    if not attributes:
        attributes = DEFAULT_RULE_TABLE_ATTRS

    if not sort_by or sort_by not in attributes:
        sort_by = "id" if "id" in attributes else attributes[0]

    rule_dicts = sorted(
        [{attr: getattr(rule, attr) for attr in attributes} for rule in rules],
        key=lambda d: d[sort_by],
    )

    print(json.dumps({"rules": rule_dicts, "total_rules": len(rule_dicts)}, indent=JSON_INDENT_LEVEL))


def print_rules_as_csv(
    rules: list[Type[Rule]],
    attributes: list[str] | None = None,
    sort_by: str | None = None,
) -> None:
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

    if not attributes:
        attributes = DEFAULT_RULE_TABLE_ATTRS

    if not sort_by or sort_by not in attributes:
        sort_by = "id" if "id" in attributes else attributes[0]

    rule_dicts = sorted(
        [{attr: getattr(rule, attr) for attr in attributes} for rule in rules],
        key=lambda d: d[sort_by],
    )

    # print the column labels as the header row
    print(",".join(attributes))

    # print the data rows
    for rule_dict in rule_dicts:
        print(",".join([pretty_format_csv(rule_dict[k]) for k in rule_dict]))


def pretty_format_csv(value: Any) -> str:
    # take care of lists by quoting them
    if isinstance(value, list):
        return f'"{",".join([str(val) for val in value])}"'

    return str(value)


def check_rule_attributes(attributes: list[str]) -> None:
    if diff := set(attributes) - set(VALID_RULE_TABLE_ATTRS):
        raise AttributeError(f"Attributes '{list(diff)}' is not allowed.")


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


def print_rule_as_text(rule: Type[Rule], original: bool) -> None:
    if original:
        rule_text = inspect.getsource(rule)
    else:
        rule_text = f"class {rule.__name__}:\n"
        rule_dict = _get_rule_dict_base(rule)
        for k, v in rule_dict.items():
            rule_text += f"    {k} = {v}\n"
    print(rule_text)
