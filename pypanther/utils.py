from enum import Enum
from typing import Any

TRUNCATED_STRING_SUFFIX = "... (truncated)"


def try_asdict(item: Any) -> Any:
    if hasattr(item, "asdict"):
        return item.asdict()
    if isinstance(item, list):
        return [try_asdict(v) for v in item]
    if isinstance(item, Enum):
        return item.value
    return item


def truncate(s: str, max_size: int):
    if len(s) > max_size:
        # If generated field exceeds max size, truncate it
        num_characters_to_keep = max_size - len(TRUNCATED_STRING_SUFFIX)
        return s[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
    return s


def dedup_list_preserving_order(items: list) -> list:
    s = set(items)
    return [item for item in items if item in s]


def _to_lowercase_set(value):
    """
    Returns a set of the given value. If the value is a string, it will be lowercased. If the value is a list, each
    item will be lowercased if it is a string. If the value is not a string or list, it will be returned as a set.
    """
    if isinstance(value, str):
        return {value.lower()}
    try:
        return {v.lower() if isinstance(v, str) else v for v in value}
    except TypeError:
        return {value}


# Get rules based on filter criteria
def filter_iterable_by_kwargs(
    iterable,
    **kwargs,
):
    return [
        x
        for x in iterable
        if all(
            _to_lowercase_set(getattr(x, key, set())).intersection(_to_lowercase_set(values))
            for key, values in kwargs.items()
            if values is not None
        )
    ]
