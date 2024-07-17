from typing import Iterable, Set, Type

from pypanther.base import Rule
from pypanther.data_models_v2 import DataModel

__RULE_REGISTRY: Set[Type[Rule]] = set()
__DATA_MODEL_REGISTRY: Set[Type[DataModel]] = set()


def register(arg: Type[Rule] | Iterable[Type[Rule]] | Type[DataModel] | Iterable[Type[DataModel]]):
    """The register function is used to register rules and data models with the pypanther library."""
    if _is_rule(arg):
        register_rule(arg)
        return
    if _is_data_model(arg):
        __DATA_MODEL_REGISTRY.add(arg)
        return

    for e in iter(arg):
        if _is_rule(e):
            register_rule(e)
        elif isinstance(e, type) and issubclass(e, DataModel):
            __DATA_MODEL_REGISTRY.add(e)
        else:
            ValueError(f"argument must be a Rule or DataModel or an iterable them not {arg}")


def register_rule(rule: Type[Rule]):
    if not _is_rule(rule):
        raise ValueError(f"rule must be a Rule subclass not {rule}")

    rule.validate()
    __RULE_REGISTRY.add(rule)


def registered_rules() -> Set[Type[Rule]]:
    return __RULE_REGISTRY


def registered_data_models() -> Set[Type[DataModel]]:
    return __DATA_MODEL_REGISTRY


def _is_rule(rule: Type[Rule]) -> bool:
    return isinstance(rule, type) and issubclass(rule, Rule)


def _is_data_model(data_model: Type[DataModel]) -> bool:
    return isinstance(data_model, type) and issubclass(data_model, DataModel)
