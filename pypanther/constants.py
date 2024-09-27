from typing import Final

VERSION_STRING: Final = "0.48.0"
CONFIG_FILE = ".panther_settings.yml"

# The UserID is required by Panther for some API calls, but we have no way of
# acquiring it, and it isn't used for anything. This is a valid UUID used by the
# Panther deployment tool to indicate this action was performed automatically.
PANTHER_USER_ID = "00000000-0000-4000-8000-000000000000"


class ReplayStatus:
    DONE = "DONE"
    CANCELED = "CANCELED"
    ERROR_EVALUATION = "ERROR_EVALUATION"
    ERROR_COMPUTATION = "ERROR_COMPUTATION"
    EVALUATION_IN_PROGRESS = "EVALUATION_IN_PROGRESS"
    COMPUTATION_IN_PROGRESS = "COMPUTATION_IN_PROGRESS"


ENABLE_CORRELATION_RULES_FLAG = "EnableCorrelationRules"
