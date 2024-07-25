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
