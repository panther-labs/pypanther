"""
Used to define global type hints for Panther events and other Panther-specific data types
"""

# Import some types for type hinting
from panther_core import PantherEvent
from panther_core.immutable import ImmutableCaseInsensitiveDict, ImmutableList

__all__ = ["PantherEvent", "ImmutableCaseInsensitiveDict", "ImmutableList"]
