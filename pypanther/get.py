from importlib import import_module
from pkgutil import walk_packages
from types import ModuleType
from typing import Any, Iterable, List, Set, Type

from pydantic import NonNegativeInt, PositiveInt

from pypanther.base import DataModel, Rule
from pypanther.severity import Severity
from pypanther.unit_tests import RuleTest
from pypanther.utils import filter_iterable_by_kwargs

__RULES: Set[Type[Rule]] = set()
__DATA_MODELS: Set[Type[DataModel]] = set()


def get_panther_rules(
    log_types: List[str] | None = None,
    id: str | None = None,
    create_alert: bool | None = None,
    dedup_period_minutes: NonNegativeInt | None = None,
    display_name: List[str] | str | None = None,
    enabled: bool | None = None,
    summary_attributes: List[str] | None = None,
    tests: List[RuleTest] | None = None,
    threshold: PositiveInt | None = None,
    tags: List[str] | None = None,
    reports: dict[str, List[str]] | None = None,
    default_severity: List[Severity] | Severity | None = None,
    default_description: str | None = None,
    default_reference: str | None = None,
    default_runbook: str | None = None,
    default_destinations: List[str] | None = None,
) -> list[Type[Rule]]:
    """
    Return an iterator of all PantherRules in the pypanther.rules based on the provided filters.
    If the filter argument is not provided, all rules are returned. If a filter value is a list, any value in the
    list will be matched in a case-insensitive manner. If a filter value is a string, the value matching is case-insensitive.
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

    return filter_iterable_by_kwargs(
        __RULES,
        **filters,
    )


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


def apply_overrides(module: Any, rules: Iterable[Type[Rule]] = []) -> list[str]:
    """
    Applies any overrides to the given rules based on the overrides declared in the given module.
    Returns a list of the modules with apply_overrides functions that were applied.

    For example: if all your PantherRule overrides are inside an "overrides" folder, you would do
    ```
    import overrides
    from pypanther import apply_overrides, get_panther_rules

    rules = get_panther_rules()
    apply_overrides(overrides, rules)
    ```
    """
    if not isinstance(module, ModuleType):
        raise TypeError(f"Expected a module, got {type(module)}")

    modules = []

    for module_info in walk_packages(module.__path__, prefix=module.__name__ + "."):
        m = import_module(module_info.name)
        # each module should have an apply_overrides function,
        # but still explictly check for it
        if "apply_overrides" in dir(m):
            m.apply_overrides(rules)
            modules.append(str(m))

    return modules


def get_panther_data_models(**kwargs) -> list[Type[DataModel]]:
    """
    Return an iterator of all PantherDataModels in the pypanther.rules based on the provided filters.
    If the filter argument is not provided, all data models are returned. If a filter value is a list, any value in the
    list will be matched in a case-insensitive manner. If a filter value is a string, the value matching is case-insensitive.
    """
    if not __DATA_MODELS:
        p_a_d = import_module("pypanther.data_models")
        for module_info in walk_packages(p_a_d.__path__, "pypanther.data_models."):
            m = import_module(module_info.name)
            for item in dir(m):
                attr = getattr(m, item)
                if isinstance(attr, type) and issubclass(attr, DataModel) and attr is not DataModel:
                    __DATA_MODELS.add(attr)

    return filter_iterable_by_kwargs(__DATA_MODELS, **kwargs)
