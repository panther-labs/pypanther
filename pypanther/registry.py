from typing import Iterable, Set, Type

from pypanther.base import Rule
from pypanther.data_models_v2 import DataModel

_RULE_REGISTRY: Set[Type[Rule]] = set()
_DATA_MODEL_REGISTRY: Set[Type[DataModel]] = set()


def register(arg: Type[Rule] | Type[DataModel] | Iterable[Type[Rule] | Type[DataModel]]) -> None:
    """The register function is used to register rules and data models with the pypanther library."""
    if _register_rule(arg):  # type: ignore
        return
    if _register_data_model(arg):  # type: ignore
        return

    try:
        it = iter(arg)  # type: ignore
    except TypeError:
        raise ValueError(f"argument must be a Rule or DataModel or an iterable of them not {arg}")

    for e in it:
        if _register_rule(e):  # type: ignore
            continue
        if _register_data_model(e):  # type: ignore
            continue
        raise ValueError(f"argument must be a Rule or DataModel or an iterable of them not {arg}")


def _register_rule(rule: Type[Rule]) -> bool:
    """Register a rule with the pypanther library. Returns True if the rule was registered, False otherwise."""

    if isinstance(rule, type) and issubclass(rule, Rule):
        rule.validate()
        _RULE_REGISTRY.add(rule)
        return True
    return False


def _register_data_model(dm: Type[DataModel]) -> bool:
    """Register a data model with the pypanther library.
    Returns True if the data model was registered, False otherwise."""

    if isinstance(dm, type) and issubclass(dm, DataModel):
        _DATA_MODEL_REGISTRY.add(dm)
        return True
    return False


def registered_rules() -> Set[Type[Rule]]:
    return _RULE_REGISTRY


def registered_data_models() -> Set[Type[DataModel]]:
    return _DATA_MODEL_REGISTRY
