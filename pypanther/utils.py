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


def __to_set(value):
    if isinstance(value, str):
        return {value}
    try:
        return set(value)
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
            __to_set(getattr(x, key, set())).intersection(__to_set(values))
            for key, values in kwargs.items()
            if values is not None
        )
    ]
