import abc
import contextlib
import copy
import inspect
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Tuple, Type, Union
from unittest.mock import MagicMock, patch

from jsonpath_ng import Fields
from jsonpath_ng.ext import parse
from panther_core.data_model import DataModel
from panther_core.detection import DetectionResult
from panther_core.enriched_event import PantherEvent
from panther_core.exceptions import FunctionReturnTypeError, UnknownDestinationError
from panther_core.util import get_bool_env_var
from pydantic import BaseModel, NonNegativeInt, PositiveInt, TypeAdapter

from pypanther.log_types import LogType
from pypanther.validate import NonEmptyUniqueList, UniqueList

logger = logging.getLogger(__name__)

# We want to default this to false as PAT will want detection output
DISABLE_OUTPUT = get_bool_env_var("DISABLE_DETECTION_OUTPUT", False)

TYPE_RULE = "RULE"
TYPE_SCHEDULED_RULE = "SCHEDULED_RULE"
TYPE_CORRELATION_RULE = "CORRELATION_RULE"

ERROR_TYPE_RULE = "RULE_ERROR"
ERROR_TYPE_SCHEDULED_RULE = "SCHEDULED_RULE_ERROR"
ERROR_TYPE_CORRELATION_RULE = "CORRELATION_RULE_ERROR"

# Maximum size for a dedup string
MAX_DEDUP_STRING_SIZE = 1000

# Maximum size for a generated field
MAX_GENERATED_FIELD_SIZE = 1000

# Maximum number of destinations
MAX_DESTINATIONS_SIZE = 10

# The limit for DDB is 400kb per item (we store this one in DDB) and
# the limit for SQS/SNS is 256KB. The limit of 200kb is an approximation - the other
# fields included in the request will be less than the remaining 56kb
MAX_ALERT_CONTEXT_SIZE = 200 * 1024  # 200kb

ALERT_CONTEXT_ERROR_KEY = "_error"

TRUNCATED_STRING_SUFFIX = "... (truncated)"

DEFAULT_DETECTION_DEDUP_PERIOD_MINS = 60

# Used to check dynamic severity output
SEVERITY_TYPES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_DEFAULT = "DEFAULT"

RULE_METHOD = "rule"

ALERT_CONTEXT_METHOD = "alert_context"
DEDUP_METHOD = "dedup"
DESCRIPTION_METHOD = "description"
DESTINATIONS_METHOD = "destinations"
REFERENCE_METHOD = "reference"
RUNBOOK_METHOD = "runbook"
SEVERITY_METHOD = "severity"
TITLE_METHOD = "title"

# Auxiliary METHODS are optional
AUXILIARY_METHODS = (
    ALERT_CONTEXT_METHOD,
    DEDUP_METHOD,
    DESCRIPTION_METHOD,
    DESTINATIONS_METHOD,
    REFERENCE_METHOD,
    RUNBOOK_METHOD,
    SEVERITY_METHOD,
    TITLE_METHOD,
)


PANTHER_RULE_ALL_METHODS = [
    RULE_METHOD,
    SEVERITY_METHOD,
    TITLE_METHOD,
    DEDUP_METHOD,
    DESTINATIONS_METHOD,
    RUNBOOK_METHOD,
    REFERENCE_METHOD,
    DESCRIPTION_METHOD,
    ALERT_CONTEXT_METHOD,
]


PANTHER_RULE_ALL_ATTRS = [
    "CreateAlert",
    "DedupPeriodMinutes",
    "Description",
    "DisplayName",
    "Enabled",
    "LogTypes",
    "OutputIds",
    "Reference",
    "Reports",
    "RuleID",
    "Runbook",
    "ScheduledQueries",
    "Severity",
    "SummaryAttributes",
    "Tags",
    "Tests",
    "Threshold",
]


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


def try_asdict(item: Any) -> Any:
    if hasattr(item, "asdict"):
        return item.asdict()
    if isinstance(item, list):
        return [try_asdict(v) for v in item]
    if isinstance(item, Enum):
        return item.value
    return item


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
        instance = super().__call__(*args, **kwargs, _file_path=file_path, _line_no=line_number)
        return instance


@dataclass
class PantherRuleTest(metaclass=FileLocationMeta):
    Name: str
    ExpectedResult: bool
    Log: Dict | str
    Mocks: List[PantherRuleMock] = field(default_factory=list)
    _file_path: str = ""
    _line_no: int = 0

    def log_data(self):
        if isinstance(self.Log, str):
            return json.loads(self.Log)
        return self.Log

    def location(self) -> str:
        return f"{self._file_path}:{self._line_no}"

    def asdict(self):
        """Returns a dictionary representation of the class."""
        return {key: try_asdict(getattr(self, key)) for key in PANTHER_RULE_TEST_ALL_ATTRS}


class PantherRuleModel(BaseModel):
    CreateAlert: bool
    DedupPeriodMinutes: NonNegativeInt
    Description: str
    DisplayName: str
    Enabled: bool
    LogTypes: NonEmptyUniqueList[str]
    OutputIds: UniqueList[str]
    Reference: str
    Reports: Dict[str, NonEmptyUniqueList[str]]
    RuleID: str
    Runbook: str
    ScheduledQueries: UniqueList[str]
    Severity: PantherSeverity
    SummaryAttributes: UniqueList[str]
    Tags: UniqueList[str]
    Tests: List[PantherRuleTest]
    Threshold: PositiveInt


PantherRuleAdapter = TypeAdapter(PantherRuleModel)


DEFAULT_CREATE_ALERT = True
DEFAULT_DEDUP_PERIOD_MINUTES = 60
DEFAULT_DESCRIPTION = ""
DEFAULT_DISPLAY_NAME = ""
DEFAULT_ENABLED = True
DEFAULT_OUTPUT_IDS: List[str] = []
DEFAULT_REFERENCE = ""
DEFAULT_REPORTS: Dict[str, List[str]] = {}
DEFAULT_RUNBOOK = ""
DEFAULT_SCHEDULED_QUERIES: List[str] = []
DEFAULT_SUMMARY_ATTRIBUTES: List[str] = []
DEFAULT_TAGS: List[str] = []
DEFAULT_TESTS: List[PantherRuleTest] = []
DEFAULT_THRESHOLD = 1


def truncate(s: str, max_size: int):
    if len(s) > max_size:
        # If generated field exceeds max size, truncate it
        num_characters_to_keep = max_size - len(TRUNCATED_STRING_SUFFIX)
        return s[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
    return s


SeverityType = Union[PantherSeverity | Literal["DEFAULT"] | str]


class PantherRule(metaclass=abc.ABCMeta):
    """A Panther rule class. This class should be subclassed to create a new rule."""

    LogTypes: List[LogType | str]
    RuleID: str
    Severity: PantherSeverity | str
    CreateAlert: bool = DEFAULT_CREATE_ALERT
    DedupPeriodMinutes: NonNegativeInt = DEFAULT_DEDUP_PERIOD_MINUTES
    Description: str = DEFAULT_DESCRIPTION
    DisplayName: str = DEFAULT_DISPLAY_NAME
    Enabled: bool = DEFAULT_ENABLED
    OutputIds: List[str] = DEFAULT_OUTPUT_IDS
    Reference: str = DEFAULT_REFERENCE
    Reports: Dict[str, List[str]] = DEFAULT_REPORTS
    Runbook: str = DEFAULT_RUNBOOK
    ScheduledQueries: List[str] = DEFAULT_SCHEDULED_QUERIES
    SummaryAttributes: List[str] = DEFAULT_SUMMARY_ATTRIBUTES
    Tags: List[str] = DEFAULT_TAGS
    Tests: List[PantherRuleTest] = DEFAULT_TESTS
    Threshold: PositiveInt = DEFAULT_THRESHOLD

    def _analysis_type(self) -> str:
        return TYPE_RULE

    @classmethod
    def is_panther_managed(cls) -> bool:
        return cls.__module__.startswith("pypanther.rules")

    @abc.abstractmethod
    def rule(self, event: PantherEvent) -> bool:
        raise NotImplementedError("You must implement the rule method in your rule class.")

    def severity(self, event: PantherEvent) -> SeverityType:
        return self.Severity

    def title(self, event: PantherEvent) -> str:
        return self.DisplayName if self.DisplayName else self.RuleID

    def dedup(self, event: PantherEvent) -> str:
        return self.title(event)

    def destinations(self, event: PantherEvent) -> List[str]:
        return self.OutputIds

    def runbook(self, event: PantherEvent) -> str:
        return self.Runbook

    def reference(self, event: PantherEvent) -> str:
        return self.Reference

    def description(self, event: PantherEvent) -> str:
        return self.Description

    def alert_context(self, event: PantherEvent) -> Dict:
        return {}

    def __init_subclass__(cls, **kwargs):
        """Creates a copy of all class attributes to avoid mod
        child.Tags.append("Foo")
        parent.Tags.append("Foo") # not inherited by children of parent
        """
        for attr in PANTHER_RULE_ALL_ATTRS:
            if attr not in cls.__dict__:
                try:
                    v = getattr(cls, attr)
                except AttributeError:
                    v = None

                if v is not None:
                    setattr(cls, attr, copy.deepcopy(v))
        super().__init_subclass__(**kwargs)

    @classmethod
    def asdict(cls):
        """Returns a dictionary representation of the class."""
        return {
            key: try_asdict(getattr(cls, key))
            for key in PANTHER_RULE_ALL_ATTRS
            if hasattr(cls, key)
        }

    @classmethod
    def validate(cls):
        PantherRuleAdapter.validate_python(cls.asdict())

        # instantiation confirms that abstract methods are implemented
        cls()

    @classmethod
    def override(
        cls,
        LogTypes: Optional[List[str]] = None,
        RuleID: Optional[str] = None,
        Severity: Optional[PantherSeverity] = None,
        CreateAlert: Optional[bool] = None,
        DedupPeriodMinutes: Optional[NonNegativeInt] = None,
        Description: Optional[str] = None,
        DisplayName: Optional[str] = None,
        Enabled: Optional[bool] = None,
        OutputIds: Optional[List[str]] = None,
        Reference: Optional[str] = None,
        Runbook: Optional[str] = None,
        Reports: Optional[Dict[str, List[str]]] = None,
        ScheduledQueries: Optional[List[str]] = None,
        SummaryAttributes: Optional[List[str]] = None,
        Tags: Optional[List[str]] = None,
        Tests: Optional[List[PantherRuleTest]] = None,
        Threshold: Optional[PositiveInt] = None,
    ):
        for key, val in locals().items():
            if key == "cls":
                continue

            if val is not None:
                setattr(cls, key, val)

    @classmethod
    def run_tests(
        cls,
        get_data_model: Callable[[str], Optional[DataModel]],
    ):
        cls.validate()
        rule = cls()
        for test in rule.Tests:
            rule.run_test(test, get_data_model)

    def run_test(
        self,
        test: PantherRuleTest,
        get_data_model: Callable[[str], Optional[DataModel]],
    ):
        log = test.log_data()
        log_type = log.get("p_log_type", "default")

        event = PantherEvent(log, get_data_model(log_type))

        patches: List[Any] = []
        for each_mock in test.Mocks:
            kwargs = {each_mock.ObjectName: MagicMock(return_value=each_mock.ReturnValue)}
            p = patch.multiple(self.__module__, **kwargs)
            try:
                p.start()
            except AttributeError:
                p = patch.multiple(self, **kwargs)
                p.start()

        try:
            detection_result = self.run(event, {}, {}, True)
            assert (
                detection_result.detection_output == test.ExpectedResult
            ), f"test '{test.Name}' returned the wrong result: {test.location()}"

            for method_name, exc in {
                "title": detection_result.title_exception,
                "description": detection_result.description_exception,
                "reference": detection_result.reference_exception,
                "severity": detection_result.severity_exception,
                "runbook": detection_result.runbook_exception,
                "destinations": detection_result.destinations_exception,
                "dedup": detection_result.dedup_exception,
                "alert_context": detection_result.alert_context_exception,
            }.items():
                if exc:
                    # log level "warning" and above is captured by the test runner
                    logging.warning(
                        "Exception in test '%s' calling %s()",
                        test.Name,
                        method_name,
                        exc_info=exc,
                    )

            assert (
                detection_result.title_exception is None
            ), "title() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.description_exception is None
            ), "description() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.reference_exception is None
            ), "reference() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.severity_exception is None
            ), "severity() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.runbook_exception is None
            ), "runbook() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.destinations_exception is None
            ), "destinations() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.dedup_exception is None
            ), "dedup() raised an exception, see the captured log output for stacktrace"
            assert (
                detection_result.alert_context_exception is None
            ), "alert_context() raised an exception, see the captured log output for stacktrace"
        finally:
            for p in patches:
                p.stop()

    def run(
        self,
        event: PantherEvent,
        outputs: Dict,
        outputs_names: Dict,
        batch_mode: bool = True,
    ) -> DetectionResult:
        result = DetectionResult(
            detection_id=self.RuleID,
            detection_severity=self.Severity,
            detection_type=TYPE_RULE,
            # set default to not alert
            trigger_alert=False,
        )

        try:
            result.detection_output = self.rule(event)
            self._require_bool(self.rule.__name__, result.detection_output)
        except Exception as e:
            result.detection_exception = e

        if isinstance(result.detection_output, bool) and result.detection_output:
            result.trigger_alert = True
        if batch_mode and not result.trigger_alert:
            # In batch mode (log analysis), there is no need to run the rest of the functions
            # if the detection isn't going to trigger an alert
            return result

        self.ctx_mgr = noop
        if DISABLE_OUTPUT:
            self.ctx_mgr = suppress_output

        result.title_output, result.title_exception = self._get_title(event)
        result.description_output, result.description_exception = self._get_description(event)
        result.reference_output, result.reference_exception = self._get_reference(event)
        result.severity_output, result.severity_exception = self._get_severity(event)
        result.runbook_output, result.runbook_exception = self._get_runbook(event)
        result.destinations_output, result.destinations_exception = self._get_destinations(
            event,
            outputs,
            outputs_names,
        )
        result.dedup_output, result.dedup_exception = self._get_dedup(event)
        result.alert_context_output, result.alert_context_exception = self._get_alert_context(event)

        if batch_mode:
            # batch mode ignores errors
            result.title_exception = None
            result.description_exception = None
            result.reference_exception = None
            result.severity_exception = None
            result.runbook_exception = None
            result.destinations_exception = None
            result.dedup_exception = None
            result.alert_context_exception = None

        return result

    def _get_title(self, event: Mapping) -> Tuple[str, Optional[Exception]]:
        try:
            with self.ctx_mgr():
                title = self.title(event)

            self._require_str(self.title.__name__, title)
        except Exception as e:
            title = self.DisplayName
            if not title or not isinstance(title, str):
                title = self.RuleID
            return title, e

        return truncate(title, MAX_GENERATED_FIELD_SIZE), None

    # Returns the dedup string for this detection match
    def _get_dedup(self, event: Mapping) -> Tuple[Optional[str], Optional[Exception]]:
        e = None
        dedup_string = ""
        try:
            with self.ctx_mgr():
                dedup_string = self.dedup(event)

            self._require_str(self.dedup.__name__, dedup_string)
        except Exception as err:
            e = err

        if dedup_string == "" or not isinstance(dedup_string, str):
            dedup_string, _ = self._get_title(event)
            if dedup_string == "" or not isinstance(dedup_string, str):
                dedup_string = f"defaultDedupString:{self.RuleID}"

        return truncate(dedup_string, MAX_DEDUP_STRING_SIZE), e

    def _get_description(
        self,
        event: Mapping,
    ) -> Tuple[str, Optional[Exception]]:
        try:
            with self.ctx_mgr():
                description = self.description(event)

            self._require_str(self.description.__name__, description)
        except Exception as e:
            return "", e

        return truncate(description, MAX_GENERATED_FIELD_SIZE), None

    def _get_reference(self, event: Mapping) -> Tuple[str, Optional[Exception]]:
        try:
            with self.ctx_mgr():
                reference = self.reference(event)

            self._require_str(self.reference.__name__, reference)
        except Exception as e:
            return "", e

        return truncate(reference, MAX_GENERATED_FIELD_SIZE), None

    def _get_runbook(self, event: Mapping) -> Tuple[Optional[str], Optional[Exception]]:
        try:
            with self.ctx_mgr():
                runbook = self.runbook(event)

            self._require_str(self.runbook.__name__, runbook)
        except Exception as e:
            return "", e

        return truncate(runbook, MAX_GENERATED_FIELD_SIZE), None

    def _get_severity(self, event: Mapping) -> Tuple[Optional[str], Optional[Exception]]:
        try:
            with self.ctx_mgr():
                severity: str = self.severity(event)

            self._require_str(self.severity.__name__, severity)
            severity = severity.upper()
            if severity == SEVERITY_DEFAULT:
                return self.Severity, None
            if severity not in SEVERITY_TYPES:
                raise AssertionError(
                    f"Expected severity to be any of the following: [{str(SEVERITY_TYPES)}], got [{severity}] instead."
                )
        except Exception as e:
            return self.Severity, e

        return severity, None

    def _get_alert_context(self, event: Mapping) -> Tuple[Optional[str], Optional[Exception]]:
        try:
            with self.ctx_mgr():
                alert_context = self.alert_context(event)

            self._require_mapping(self.alert_context.__name__, alert_context)
            serialized_alert_context = json.dumps(alert_context, default=PantherEvent.json_encoder)
        except Exception as err:
            return json.dumps({ALERT_CONTEXT_ERROR_KEY: repr(err)}), err

        if len(serialized_alert_context) > MAX_ALERT_CONTEXT_SIZE:
            # If context exceeds max size, return empty one
            alert_context_error = (
                f"alert_context size is [{len(serialized_alert_context)}] characters,"
                f" bigger than maximum of [{MAX_ALERT_CONTEXT_SIZE}] characters"
            )
            return json.dumps({ALERT_CONTEXT_ERROR_KEY: alert_context_error}), None

        return serialized_alert_context, None

    def _get_destinations(
        self,
        event: Mapping,
        outputs: Dict,
        outputs_display_names: Dict,
    ) -> Tuple[Optional[List[str]], Optional[Exception]]:
        try:
            with self.ctx_mgr():
                destinations = self.destinations(event)
            self._require_str_list(self.destinations.__name__, destinations)
        except Exception as e:
            return None, e

        # Return early if destinations returned None
        if destinations is None:
            return None, None

        # Return early if destinations is an empty list (alert dest. suppression)
        if len(destinations) == 0:
            return ["SKIP"], None

        # Check for (in)valid destinations
        invalid_destinations = []
        standardized_destinations: List[str] = []

        # Standardize the destinations
        for each_destination in destinations:
            # case for valid display name
            if (
                each_destination in outputs_display_names
                and outputs_display_names[each_destination].destination_id
                not in standardized_destinations
            ):
                standardized_destinations.append(
                    outputs_display_names[each_destination].destination_id
                )
            # case for valid UUIDv4
            elif each_destination in outputs and each_destination not in standardized_destinations:
                standardized_destinations.append(each_destination)
            else:
                invalid_destinations.append(each_destination)

        if invalid_destinations:
            try:
                # raise to get a stack trace
                raise UnknownDestinationError("Invalid Destinations", invalid_destinations)
            except UnknownDestinationError as e:
                return None, e

        if len(standardized_destinations) > MAX_DESTINATIONS_SIZE:
            # If generated field exceeds max size, truncate it
            standardized_destinations = standardized_destinations[:MAX_DESTINATIONS_SIZE]

        return standardized_destinations, None

    def _require_bool(self, method_name: str, value: Any):
        return self._require_scalar(method_name, bool, value)

    def _require_str(self, method_name: str, value: Any):
        return self._require_scalar(method_name, str, value)

    def _require_mapping(self, method_name: str, value: Any):
        return self._require_scalar(method_name, Mapping, value)

    def _require_scalar(self, method_name: str, typ: Type, value: Any):
        if not isinstance(value, typ):
            raise FunctionReturnTypeError(
                f"detection [{self.RuleID}] method [{method_name}] returned [{type(value).__name__}], expected [{typ.__name__}]"
            )

    def _require_str_list(self, method_name: str, value: Any):
        if value is None:
            return
        if not isinstance(value, list) or not all(isinstance(x, (str, bool)) for x in value):
            raise FunctionReturnTypeError(
                "detection [{}] method [{}] returned [{}], expected a list".format(
                    self.RuleID, method_name, type(value).__name__
                )
            )


@contextlib.contextmanager
def suppress_output():
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")
    try:
        yield
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr


@contextlib.contextmanager
def noop():
    yield


@dataclass
class PantherDataModelMapping:
    Name: str
    Path: Optional[str] = None
    Method: Optional[Callable] = None


class PantherDataModel:
    DataModelID: str
    DisplayName: str
    Enabled: bool
    LogTypes: List[str]
    Mappings: List[PantherDataModelMapping]

    def __init__(self) -> None:
        self.paths: Dict[str, Fields] = {}
        self.methods: Dict[str, Callable] = {}

        for mapping in self.Mappings:
            if not mapping.Name:
                raise AssertionError(
                    f"DataModel [{self.DataModelID}] is missing required field: [Name]"
                )
            if mapping.Path:
                self.paths[mapping.Name] = parse(mapping.Path)
            elif mapping.Method:
                self.methods[mapping.Name] = mapping.Method
            else:
                raise AssertionError(
                    f"DataModel [{self.DataModelID}] must define one of: [Path, Method]"
                )
