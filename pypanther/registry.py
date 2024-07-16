from typing import Iterable, Set, Type

from pypanther.base import Rule

__REGISTRY: Set[Type[Rule]] = set()


def register(rule: Type[Rule] | Iterable[Type[Rule]]):
    if isinstance(rule, type) and issubclass(rule, Rule):
        register_rule(rule)
        return
    try:
        for r in iter(rule):
            register_rule(r)
        return
    except TypeError:
        pass

    raise ValueError(f"rule must be a Rule or an iterable of Rule not {rule}")


def register_rule(rule: Type[Rule]):
    if not isinstance(rule, type) and issubclass(rule, Rule):
        raise ValueError(f"rule must be a Rule subclass not {rule}")

    rule.validate()
    __REGISTRY.add(rule)


def registered_rules() -> Set[Type[Rule]]:
    return __REGISTRY
