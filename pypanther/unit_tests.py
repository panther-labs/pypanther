import inspect
import json
from dataclasses import dataclass, field
from typing import Any

from panther_core.detection import DetectionResult

from pypanther.utils import try_asdict

PANTHER_RULE_TEST_ALL_ATTRS = [
    "name",
    "expected_result",
    "log",
    "mocks",
]

PANTHER_RULE_MOCK_ALL_ATTRS = [
    "object_name",
    "return_value",
    "side_effect",
]


@dataclass
class PantherRuleMock:
    object_name: str
    return_value: Any = None
    side_effect: Any = None

    def asdict(self):
        """Returns a dictionary representation of the class."""
        return {key: try_asdict(getattr(self, key)) for key in PANTHER_RULE_MOCK_ALL_ATTRS}


class FileLocationMeta(type):
    def __call__(cls, *args, **kwargs):
        frame = inspect.currentframe().f_back
        file_path = frame.f_globals.get("__file__", None)
        line_number = frame.f_lineno
        module = frame.f_globals.get("__name__", None)
        instance = super().__call__(
            *args, **kwargs, _file_path=file_path, _line_no=line_number, _module=module
        )
        return instance


@dataclass
class PantherRuleTest(metaclass=FileLocationMeta):
    name: str
    expected_result: bool
    log: dict | str
    mocks: list[PantherRuleMock] = field(default_factory=list)
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
        return {key: try_asdict(getattr(self, key)) for key in PANTHER_RULE_TEST_ALL_ATTRS}


@dataclass
class PantherRuleTestResult:
    """
    PantherRuleTestResult is the output returned from running a PantherRuleTest
    on a PantherRule.

    Attributes:
        passed: If true, the PantherRuleTest passed. False, otherwise.
        detection_result: The result of the run() function on the given PantherEvent.
        test: The test that was given and created this result.
        rule_id: The ID of the PantherRule the PantherRuleTest was run on.
    """

    passed: bool
    detection_result: DetectionResult
    test: PantherRuleTest
    rule_id: str
