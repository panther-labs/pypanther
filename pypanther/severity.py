from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(str, Enum):
    info = "INFO"
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"

    def __lt__(self, other):
        return Severity.as_int(self.value) < Severity.as_int(other.value)

    @staticmethod
    def as_int(value: "Severity") -> int:
        if value.upper() == Severity.info:
            return 0
        if value.upper() == Severity.low:
            return 1
        if value.upper() == Severity.medium:
            return 2
        if value.upper() == Severity.high:
            return 3
        if value.upper() == Severity.critical:
            return 4
        raise ValueError(f"Unknown severity: {value}")

    def __str__(self) -> str:
        """Returns a string representation of the class' value."""
        return self.value


# Used to check dynamic severity output
SEVERITY_DEFAULT = "DEFAULT"
SEVERITY_TYPES = [str(sev) for sev in Severity]
