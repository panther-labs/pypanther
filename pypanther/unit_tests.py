import inspect
import json
from dataclasses import dataclass, field
from typing import Any

from panther_core.detection import DetectionResult

from pypanther.utils import try_asdict

PANTHER_RULE_TEST_ALL_ATTRS = [
    "Name",
    "ExpectedResult",
    "Log",
    "Mocks",
]

PANTHER_RULE_MOCK_ALL_ATTRS = [
    "ObjectName",
    "ReturnValue",
    "SideEffect",
]


@dataclass
class PantherRuleMock:
    ObjectName: str
    ReturnValue: Any = None
    SideEffect: Any = None

    def asdict(self):
        """Returns a dictionary representation of the class."""
        return {key: try_asdict(getattr(self, key)) for key in PANTHER_RULE_MOCK_ALL_ATTRS}


class FileLocationMeta(type):
    def __call__(cls, *args, **kwargs):
        frame = inspect.currentframe().f_back
        file_path = frame.f_globals.get("__file__", None)
        line_number = frame.f_lineno
        module = frame.f_globals.get("__name__", None)
        instance = super().__call__(*args, **kwargs, _file_path=file_path, _line_no=line_number, _module=module)
        return instance


@dataclass
class PantherRuleTest(metaclass=FileLocationMeta):
    Name: str
    ExpectedResult: bool
    Log: dict | str
    Mocks: list[PantherRuleMock] = field(default_factory=list)
    _file_path: str = ""
    _line_no: int = 0
    _module: str = ""

    def log_data(self):
        if isinstance(self.Log, str):
            return json.loads(self.Log)
        return self.Log

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
        Passed: If true, the PantherRuleTest passed. False, otherwise.
        DetectionResult: The result of the run() function on the given PantherEvent.
        Test: The test that was given and created this result.
        RuleID: The ID of the PantherRule the PantherRuleTest was run on.
    """

    Passed: bool
    DetectionResult: DetectionResult
    Test: PantherRuleTest
    RuleID: str
