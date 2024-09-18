from __future__ import annotations

from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other):
        return Severity.as_int(self.value) < Severity.as_int(other.value)

    def _increment(self, amt: int = 1) -> Severity:
        """Increase or decrease the severity level by a given amount."""
        levels = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        current_idx = levels.index(self)
        # Change index by ammount, clamping between 0 and 4
        new_idx = min(max(0, current_idx + amt), len(levels) - 1)
        return levels[new_idx]

    def upgrade(self):
        """
        Increase the severity level by 1. i.e. MEDIUM -> HIGH.
        Cannot return higher than CRITICAL.
        """
        return self._increment(1)

    def downgrade(self):
        """
        Decrease the severity level by 1. i.e. MEDIUM -> LOW.
        Cannot return lower than INFO.
        """
        return self._increment(-1)

    @staticmethod
    def as_int(value: Severity) -> int:
        val = value.upper()
        if val == Severity.INFO:
            return 0
        if val == Severity.LOW:
            return 1
        if val == Severity.MEDIUM:
            return 2
        if val == Severity.HIGH:
            return 3
        if val == Severity.CRITICAL:
            return 4
        raise ValueError(f"Unknown severity: {value}")

    def __str__(self) -> str:
        """Returns a string representation of the class' value."""
        return self.value


# Used to check dynamic severity output
SEVERITY_DEFAULT = "DEFAULT"
SEVERITY_TYPES = [str(sev) for sev in Severity]
