from enum import Enum
from functools import total_ordering


@total_ordering
class PantherSeverity(str, Enum):
    info = "INFO"
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"

    def __lt__(self, other):
        return PantherSeverity.as_int(self.value) < PantherSeverity.as_int(other.value)

    @staticmethod
    def as_int(value: "PantherSeverity") -> int:
        if value.upper() == PantherSeverity.info:
            return 0
        if value.upper() == PantherSeverity.low:
            return 1
        if value.upper() == PantherSeverity.medium:
            return 2
        if value.upper() == PantherSeverity.high:
            return 3
        if value.upper() == PantherSeverity.critical:
            return 4
        raise ValueError(f"Unknown severity: {value}")

    def __str__(self) -> str:
        """Returns a string representation of the class' value."""
        return self.value


# Used to check dynamic severity output
SEVERITY_DEFAULT = "DEFAULT"
SEVERITY_TYPES = [str(sev) for sev in PantherSeverity]
