from importlib import import_module
from pkgutil import walk_packages
from typing import Set, Type

from pypanther.base import PantherDataModel, PantherRule

__RULES: Set[Type[PantherRule]] = set()


def __to_set(value):
    if isinstance(value, str):
        return {value}
    try:
        return set(value)
    except TypeError:
        return {value}


def get_panther_rules(**kwargs):
    """Return an iterator of all PantherRules in the pypanther.rules based on the provided filters.
    If the filter argument is not provided, all rules are returned. If a filter value is a list, any value in the
    list will match. If a filter value is a string, the value must match exactly.
    """
    if not __RULES:
        p_a_r = import_module("pypanther.rules")
        for module_info in walk_packages(p_a_r.__path__, "pypanther.rules."):
            if len(module_info.name.split(".")) > 3:
                m = import_module(module_info.name)
                for item in dir(m):
                    attr = getattr(m, item)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, PantherRule)
                        and attr is not PantherRule
                    ):
                        if not hasattr(attr, "RuleID"):
                            continue
                        __RULES.add(attr)

    return filter_kwargs(__RULES, **kwargs)


__DATA_MODELS: Set[Type[PantherRule]] = set()


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
                if (
                    isinstance(attr, type)
                    and issubclass(attr, PantherDataModel)
                    and attr is not PantherDataModel
                ):
                    __DATA_MODELS.add(attr)

    return filter_kwargs(__DATA_MODELS, **kwargs)


# Get rules based on filter criteria
def filter_kwargs(
    iterable,
    **kwargs,
):
    return [
        x
        for x in iterable
        if all(
            __to_set(getattr(x, key, set())).intersection(__to_set(values))
            for key, values in kwargs.items()
        )
    ]
