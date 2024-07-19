import pprint
from importlib import import_module
from pkgutil import walk_packages
from types import ModuleType
from typing import Any, List, Set, Type

from prettytable import PrettyTable
from pydantic import PositiveInt, NonNegativeInt

from pypanther.severity import Severity
from pypanther.unit_tests import RuleTest
from pypanther.base import DataModel, Rule

__RULES: Set[Type[Rule]] = set()


def __to_set(value):
    if isinstance(value, str):
        return {value}
    try:
        return set(value)
    except TypeError:
        return {value}


def get_panther_rules(
    log_types: List[str] | None = None,
    id: str | None = None,
    create_alert: bool | None = None,
    dedup_period_minutes: NonNegativeInt | None = None,
    display_name: str | None = None,
    enabled: bool | None = None,
    scheduled_queries: List[str] | None = None,
    summary_attributes: List[str] | None = None,
    tests: List[RuleTest] | None = None,
    threshold: PositiveInt | None = None,
    tags: List[str] | None = None,
    reports: dict[str, List[str]] | None = None,
    default_severity: Severity | None = None,
    default_description: str | None = None,
    default_reference: str | None = None,
    default_runbook: str | None = None,
    default_destinations: List[str] | None = None,
) -> list[Type[Rule]]:
    """Return an iterator of all PantherRules in the pypanther.rules based on the provided filters.
    If the filter argument is not provided, all rules are returned. If a filter value is a list, any value in the
    list will match. If a filter value is a string, the value must match exactly.
    """
    filters = locals()

    if not __RULES:
        p_a_r = import_module("pypanther.rules")
        for module_info in walk_packages(p_a_r.__path__, "pypanther.rules."):
            if len(module_info.name.split(".")) > 3:
                m = import_module(module_info.name)
                for item in dir(m):
                    attr = getattr(m, item)
                    if isinstance(attr, type) and issubclass(attr, Rule) and attr is not Rule:
                        if not hasattr(attr, "id"):
                            continue
                        __RULES.add(attr)

    print(len(__RULES))
    return filter_kwargs(
        __RULES,
        **filters,
    )


__DATA_MODELS: Set[Type[Rule]] = set()


def get_rules(module: Any) -> list[Type[Rule]]:
    """
    Returns a list of PantherRule subclasses that are declared within the given module, recursively.
    All sub-packages of the given module must have an __init__.py declared for PantherRule subclasses
    to be included.

    For example: if all your PantherRule subclasses are inside a "rules" folder, you would do
    ```
    import rules
    from pypanther import get_rules, register

    custom_rules = get_rules(rules)
    register(custom_rules)
    ```
    """
    if not isinstance(module, ModuleType):
        raise TypeError(f"Expected a module, got {type(module)}")

    subclasses = set()

    for module_info in walk_packages(module.__path__, prefix=module.__name__ + "."):
        m = import_module(module_info.name)

        for item in dir(m):
            attr = getattr(m, item)
            if isinstance(attr, type) and issubclass(attr, Rule) and attr is not Rule:
                if not hasattr(attr, "id"):
                    continue
                subclasses.add(attr)

    return list(subclasses)


def get_panther_data_models(**kwargs):
    """Return an iterator of all PantherDataModels in the pypanther.rules based on the provided filters.
    If the filter argument is not provided, all data models are returned. If a filter value is a list, any value in the
    list will match. If a filter value is a string, the value must match exactly.
    """
    if not __DATA_MODELS:
        p_a_d = import_module("pypanther.data_models")
        for module_info in walk_packages(p_a_d.__path__, "pypanther.data_models."):
            m = import_module(module_info.name)
            for item in dir(m):
                attr = getattr(m, item)
                if isinstance(attr, type) and issubclass(attr, DataModel) and attr is not DataModel:
                    __DATA_MODELS.add(attr)

    return filter_kwargs(__DATA_MODELS, **kwargs)


# Get rules based on filter criteria
def filter_kwargs(
    iterable,
    **kwargs,
):
    pprint.pprint(kwargs)
    return [
        x
        for x in iterable
        if all(
            __to_set(getattr(x, key, set())).intersection(__to_set(values))
            for key, values in kwargs.items()
            if values is not None
        )
    ]


def print_rule_table(rules: List[Type[Rule]]) -> None:
    """Prints rules in a table format for easy viewing."""
    table = PrettyTable()
    table.field_names = [
        "RuleID",
        "LogTypes",
        "DisplayName",
        "Severity",
        "Enabled",
        "CreateAlert",
    ]

    for rule in rules:
        log_types = rule.log_types
        if len(log_types) > 2:
            log_types = log_types[:2] + ["+{}".format(len(log_types) - 2)]

        table.add_row(
            [
                rule.id,
                ", ".join([str(s) for s in log_types]),
                rule.display_name,
                rule.default_severity,
                rule.enabled,
                rule.create_alert,
            ]
        )
    table.sortby = "RuleID"

    print(table)
