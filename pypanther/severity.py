from enum import Enum
from functools import total_ordering

# Used to check dynamic severity output
SEVERITY_TYPES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_DEFAULT = "DEFAULT"


@total_ordering
class PantherSeverity(str, Enum):
    Info = "Info"
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

    def __lt__(self, other):
        return PantherSeverity.as_int(self.value) < PantherSeverity.as_int(other.value)

    @staticmethod
    def as_int(value: "PantherSeverity") -> int:
        if value.upper() == PantherSeverity.Info.upper():
            return 0
        if value.upper() == PantherSeverity.Low.upper():
            return 1
        if value.upper() == PantherSeverity.Medium.upper():
            return 2
        if value.upper() == PantherSeverity.High.upper():
            return 3
        if value.upper() == PantherSeverity.Critical.upper():
            return 4
        raise ValueError(f"Unknown severity: {value}")

    def __str__(self) -> str:
        """Returns a string representation of the class' value."""
        return self.value
