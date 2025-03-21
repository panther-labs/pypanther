from typing import Iterable, List, Set, Type

from pydantic import NonNegativeInt, PositiveInt

from pypanther.base import Rule
from pypanther.data_models_v2 import DataModel
from pypanther.severity import Severity
from pypanther.unit_tests import RuleTest
from pypanther.utils import filter_iterable_by_kwargs

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
    """
    Register a data model with the pypanther library.
    Returns True if the data model was registered, False otherwise.
    """
    if isinstance(dm, type) and issubclass(dm, DataModel):
        _DATA_MODEL_REGISTRY.add(dm)
        return True
    return False


def registered_rules(
    log_types: List[str] | None = None,
    id: str | None = None,
    create_alert: bool | None = None,
    dedup_period_minutes: NonNegativeInt | None = None,
    display_name: str | None = None,
    enabled: bool | None = None,
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
) -> Set[Type[Rule]]:
    filters = locals()
    return set(
        filter_iterable_by_kwargs(
            _RULE_REGISTRY,
            **filters,
        ),
    )


def registered_data_models() -> Set[Type[DataModel]]:
    return _DATA_MODEL_REGISTRY
