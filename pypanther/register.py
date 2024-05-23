from typing import Iterable, Set, Type

from pypanther.base import PantherRule

__REGISTRY: Set[Type[PantherRule]] = set()


def register(rule: Type[PantherRule] | Iterable[Type[PantherRule]]):
    if isinstance(rule, type) and issubclass(rule, PantherRule):
        register_rule(rule)
        return
    try:
        for r in iter(rule):
            register_rule(r)
        return
    except TypeError:
        pass

    raise ValueError(f"rule must be a PantherRule or an iterable of PantherRule not {rule}")


def register_rule(rule: Type[PantherRule]):
    if not isinstance(rule, type) and issubclass(rule, PantherRule):
        raise ValueError(f"rule must be a PantherRule subclass not {rule}")

    rule.validate()
    __REGISTRY.add(rule)


def registered_rules() -> Set[Type[PantherRule]]:
    return __REGISTRY
