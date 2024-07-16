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

    @staticmethod
    def as_int(value: "Severity") -> int:
        if value.upper() == Severity.INFO:
            return 0
        if value.upper() == Severity.LOW:
            return 1
        if value.upper() == Severity.MEDIUM:
            return 2
        if value.upper() == Severity.HIGH:
            return 3
        if value.upper() == Severity.CRITICAL:
            return 4
        raise ValueError(f"Unknown severity: {value}")

    def __str__(self) -> str:
        """Returns a string representation of the class' value."""
        return self.value


# Used to check dynamic severity output
SEVERITY_DEFAULT = "DEFAULT"
SEVERITY_TYPES = [str(sev) for sev in Severity]
