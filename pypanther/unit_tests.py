import inspect
import json
from dataclasses import dataclass, field
from typing import Any

from panther_core.detection import DetectionResult

from pypanther.severity import Severity
from pypanther.utils import try_asdict

RULE_TEST_ALL_ATTRS = [
    "name",
    "expected_result",
    "log",
    "mocks",
    "expected_severity",
    "expected_title",
    "expected_dedup",
    "expected_runbook",
    "expected_reference",
    "expected_description",
    "expected_alert_context",
]

RULE_MOCK_ALL_ATTRS = [
    "object_name",
    "return_value",
    "side_effect",
]

RULE_TEST_RESULT_ALL_ATTRS = [
    "passed",
    "detection_result",
    "test",
    "rule_id",
]


@dataclass
class RuleMock:
    object_name: str
    return_value: Any = None
    side_effect: Any = None
    new: Any = None

    def asdict(self):
        """Returns a dictionary representation of the class."""
        return {key: try_asdict(getattr(self, key)) for key in RULE_MOCK_ALL_ATTRS}


class FileLocationMeta(type):
    def __call__(cls, *args, **kwargs):
        frame = inspect.currentframe().f_back
        file_path = frame.f_globals.get("__file__", None)
        line_number = frame.f_lineno
        module = frame.f_globals.get("__name__", None)
        instance = super().__call__(*args, **kwargs, _file_path=file_path, _line_no=line_number, _module=module)
        return instance


@dataclass
class RuleTest(metaclass=FileLocationMeta):
    name: str
    expected_result: bool
    log: dict | str
    mocks: list[RuleMock] = field(default_factory=list)
    expected_severity: Severity | str | None = None
    expected_title: str | None = None
    expected_dedup: str | None = None
    expected_runbook: str | None = None
    expected_reference: str | None = None
    expected_description: str | None = None
    expected_alert_context: dict | None = None
    # expected_destinations is not included here because the `destinations` function
    # checks a list of valid destinations to check if the destination exists, and if it is
    # the name of the destination, it gets the id of it. pypanther does not provide support
    # for supplying that list to tests yet so this aux check is excluded.
    _file_path: str = ""
    _line_no: int = 0
    _module: str = ""

    def log_data(self):
        if isinstance(self.log, str):
            return json.loads(self.log)
        return self.log

    def location(self) -> str:
        return f"{self._file_path}:{self._line_no}"

    def asdict(self):
        """Returns a dictionary representation of the class."""
        return {key: try_asdict(getattr(self, key)) for key in RULE_TEST_ALL_ATTRS}


@dataclass
class RuleTestResult:
    """
    PantherRuleTestResult is the output returned from running a PantherRuleTest
    on a PantherRule.

    Attributes
    ----------
        passed: If true, the PantherRuleTest passed. False, otherwise.
        detection_result: The result of the run() function on the given PantherEvent.
        test: The test that was given and created this result.
        rule_id: The ID of the PantherRule the PantherRuleTest was run on.

    """

    passed: bool
    detection_result: DetectionResult
    test: RuleTest
    rule_id: str
