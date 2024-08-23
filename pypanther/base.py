import abc
import contextlib
import copy
import json
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Tuple, Type, Union
from unittest.mock import MagicMock, patch

from jsonpath_ng import Fields
from jsonpath_ng.ext import parse
from panther_core.detection import DetectionResult
from panther_core.enriched_event import PantherEvent
from panther_core.exceptions import FunctionReturnTypeError, UnknownDestinationError
from panther_core.util import get_bool_env_var
from pydantic import BaseModel, NonNegativeInt, PositiveInt, TypeAdapter

from pypanther.log_types import LogType
from pypanther.severity import SEVERITY_DEFAULT, SEVERITY_TYPES, Severity
from pypanther.unit_tests import RuleTest, RuleTestResult
from pypanther.utils import truncate, try_asdict
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

DEFAULT_DETECTION_DEDUP_PERIOD_MINS = 60

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

RULE_ALL_METHODS = [
    RULE_METHOD,
    *AUXILIARY_METHODS,
]

RULE_ALL_ATTRS = [
    "create_alert",
    "dedup_period_minutes",
    "display_name",
    "enabled",
    "log_types",
    "id",
    "scheduled_queries",
    "summary_attributes",
    "tests",
    "threshold",
    "tags",
    "reports",
    "default_severity",
    "default_description",
    "default_destinations",
    "default_runbook",
    "default_reference",
]


@dataclass
class DataModelMapping:
    name: str
    path: Optional[str] = None
    method: Optional[Callable] = None


class DataModel:
    id: str
    display_name: str
    enabled: bool
    log_types: List[str]
    mappings: List[DataModelMapping]

    def __init__(self) -> None:
        self.paths: Dict[str, Fields] = {}
        self.methods: Dict[str, Callable] = {}

        for mapping in self.mappings:
            if not mapping.name:
                raise AssertionError(f"DataModel [{self.id}] is missing required field: [Name]")
            if mapping.path:
                self.paths[mapping.name] = parse(mapping.path)
            elif mapping.method:
                self.methods[mapping.name] = mapping.method
            else:
                raise AssertionError(f"DataModel [{self.id}] must define one of: [Path, Method]")


class RuleModel(BaseModel):
    create_alert: bool
    dedup_period_minutes: NonNegativeInt
    display_name: str
    enabled: bool
    log_types: NonEmptyUniqueList[str]
    id: str
    scheduled_queries: UniqueList[str]
    summary_attributes: UniqueList[str]
    tests: List[RuleTest]
    threshold: PositiveInt
    tags: UniqueList[str]
    reports: Dict[str, NonEmptyUniqueList[str]]
    default_destinations: UniqueList[str]
    default_description: str
    default_runbook: str
    default_reference: str
    default_severity: Severity


RuleAdapter = TypeAdapter(RuleModel)

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
DEFAULT_TESTS: List[RuleTest] = []
DEFAULT_THRESHOLD = 1

SeverityType = Union[Severity | Literal["DEFAULT"] | str]


class Rule(metaclass=abc.ABCMeta):
    """A Panther rule class. This class should be subclassed to create a new rule."""

    log_types: List[LogType | str]
    id: str
    create_alert: bool = DEFAULT_CREATE_ALERT
    dedup_period_minutes: NonNegativeInt = DEFAULT_DEDUP_PERIOD_MINUTES
    display_name: str = DEFAULT_DISPLAY_NAME
    enabled: bool = DEFAULT_ENABLED
    scheduled_queries: List[str] = DEFAULT_SCHEDULED_QUERIES
    summary_attributes: List[str] = DEFAULT_SUMMARY_ATTRIBUTES
    tests: List[RuleTest] = DEFAULT_TESTS
    threshold: PositiveInt = DEFAULT_THRESHOLD
    tags: List[str] = DEFAULT_TAGS
    reports: Dict[str, List[str]] = DEFAULT_REPORTS

    default_severity: Severity | str
    default_destinations: List[str] = DEFAULT_OUTPUT_IDS
    default_runbook: str = DEFAULT_RUNBOOK
    default_reference: str = DEFAULT_REFERENCE
    default_description: str = DEFAULT_DESCRIPTION

    def __str__(self) -> str:
        return str(vars(self))

    def _analysis_type(self) -> str:
        return TYPE_RULE

    @classmethod
    def is_panther_managed(cls) -> bool:
        return getattr(cls, "_panther_managed", False) is True

    @abc.abstractmethod
    def rule(self, event: PantherEvent) -> bool:
        raise NotImplementedError("You must implement the rule method in your rule class.")

    def severity(self, event: PantherEvent) -> SeverityType:
        return self.default_severity

    def title(self, event: PantherEvent) -> str:
        return self.display_name if self.display_name else self.id

    def dedup(self, event: PantherEvent) -> str:
        return self.title(event)

    def destinations(self, event: PantherEvent) -> list[str]:
        return self.default_destinations

    def runbook(self, event: PantherEvent) -> str:
        return self.default_runbook

    def reference(self, event: PantherEvent) -> str:
        return self.default_reference

    def description(self, event: PantherEvent) -> str:
        return self.default_description

    def alert_context(self, event: PantherEvent) -> dict:
        return {}

    def __init_subclass__(cls, **kwargs):
        """
        Creates a copy of all class attributes to avoid mod
        child.tags.append("Foo")
        parent.tags.append("Foo") # not inherited by children of parent
        """
        for attr in RULE_ALL_ATTRS:
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
        return {key: try_asdict(getattr(cls, key)) for key in RULE_ALL_ATTRS if hasattr(cls, key)}

    @classmethod
    def validate_config(cls) -> None:
        """To be defined by subclasses when an out-of-the-box rules requires configuration before use."""

    @classmethod
    def validate(cls, _validate_config: bool = True) -> None:
        """
        Validates this PantherRule.

        Parameters
        ----------
            _validate_config: true if any configuration should be validated, false otherwise. Only meant to be used by Panther.

        """
        RuleAdapter.validate_python(cls.asdict())
        if _validate_config:
            cls.validate_config()

        # instantiation confirms that abstract methods are implemented
        cls()

    @classmethod
    def override(
        cls,
        log_types: Optional[List[str]] = None,
        id: Optional[str] = None,
        create_alert: Optional[bool] = None,
        dedup_period_minutes: Optional[NonNegativeInt] = None,
        display_name: Optional[str] = None,
        enabled: Optional[bool] = None,
        scheduled_queries: Optional[List[str]] = None,
        summary_attributes: Optional[List[str]] = None,
        tests: Optional[List[RuleTest]] = None,
        threshold: Optional[PositiveInt] = None,
        tags: Optional[List[str]] = None,
        reports: Optional[Dict[str, List[str]]] = None,
        default_severity: Optional[Severity] = None,
        default_description: Optional[str] = None,
        default_reference: Optional[str] = None,
        default_runbook: Optional[str] = None,
        default_destinations: Optional[List[str]] = None,
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
        _validate_config: bool = True,
        test_names: Optional[List[str]] = None,
    ) -> list[RuleTestResult]:
        """
        Runs all RuleTests in this Rules' Test attribute over this Rule.

        Parameters
        ----------
            get_data_model: a helper function that will return a DataModel given a log type.
            _validate_config: true if tests are being run should validate any configuration, false otherwise. Only meant to be used by Panther.
            test_names: if provided, the names of the tests on the rule to run, otherwise run all tests

        Returns
        -------
            a list of RuleTestResult objects.

        """
        cls.validate(_validate_config)
        rule = cls()

        if test_names is not None:
            return [rule.run_test(test, get_data_model) for test in rule.tests if test.name in test_names]

        return [rule.run_test(test, get_data_model) for test in rule.tests]

    def run_test(
        self,
        test: RuleTest,
        get_data_model: Callable[[str], Optional[DataModel]],
    ) -> RuleTestResult:
        """
        Runs a unit test over this Rule.

        Parameters
        ----------
            test: the RuleTest to run.
            get_data_model: a helper function that will return a DataModel given a log type.

        Returns
        -------
            a RuleTestResult with the test result. If the Passed attribute is True,
            then this tests passed.

        """
        log = test.log_data()
        log_type = log.get("p_log_type", "default")

        event = PantherEvent(log, get_data_model(log_type))

        patches: list[Any] = []
        for each_mock in test.mocks:
            kwargs = {
                each_mock.object_name: MagicMock(
                    return_value=each_mock.return_value,
                    side_effect=each_mock.side_effect,
                ),
            }
            if each_mock.new is not None:
                kwargs[each_mock.object_name] = each_mock.new
            p = patch.multiple(test._module, **kwargs)
            try:
                p.start()
            except AttributeError:
                p = patch.multiple(self, **kwargs)
                p.start()

        try:
            detection_result = self.run(event, {}, {}, False)

            if (
                detection_result.detection_exception is not None
                or detection_result.detection_output != test.expected_result
            ):
                return RuleTestResult(
                    passed=False,
                    detection_result=detection_result,
                    test=test,
                    rule_id=self.id,
                )

            if isinstance(detection_result.destinations_exception, UnknownDestinationError):
                # ignore unknown destinations during testing
                detection_result.destinations_exception = None

            aux_func_exceptions = {
                "title": detection_result.title_exception,
                "description": detection_result.description_exception,
                "reference": detection_result.reference_exception,
                "severity": detection_result.severity_exception,
                "runbook": detection_result.runbook_exception,
                "destinations": detection_result.destinations_exception,
                "dedup": detection_result.dedup_exception,
                "alert_context": detection_result.alert_context_exception,
            }

            if any(True for _, exc in aux_func_exceptions.items() if exc is not None):
                return RuleTestResult(
                    passed=False,
                    detection_result=detection_result,
                    test=test,
                    rule_id=self.id,
                )

            if any(
                [
                    test.expected_severity is not None and test.expected_severity != detection_result.severity_output,
                    test.expected_title is not None and test.expected_title != detection_result.title_output,
                    test.expected_dedup is not None and test.expected_dedup != detection_result.dedup_output,
                    test.expected_runbook is not None and test.expected_runbook != detection_result.runbook_output,
                    test.expected_reference is not None
                    and test.expected_reference != detection_result.reference_output,
                    test.expected_description is not None
                    and test.expected_description != detection_result.description_output,
                    test.expected_alert_context is not None
                    and test.expected_alert_context != json.loads(detection_result.alert_context_output),
                ],
            ):
                return RuleTestResult(
                    passed=False,
                    detection_result=detection_result,
                    test=test,
                    rule_id=self.id,
                )

        finally:
            for p in patches:
                p.stop()

        return RuleTestResult(
            passed=True,
            detection_result=detection_result,
            test=test,
            rule_id=self.id,
        )

    def run(
        self,
        event: PantherEvent,
        outputs: Dict,
        outputs_names: Dict,
        batch_mode: bool = True,
    ) -> DetectionResult:
        result = DetectionResult(
            detection_id=self.id,
            detection_severity=self.default_severity,
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
            # in the panther backend, we check if any error occured during running and if we get one,
            # we return a detection error instead of an alert. To make sure alerts are still returned,
            # we need to set these to None.
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
            title = self.display_name
            if not title or not isinstance(title, str):
                title = self.id
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
                dedup_string = f"defaultDedupString:{self.id}"

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
                return self.default_severity, None
            if severity not in SEVERITY_TYPES:
                raise AssertionError(
                    f"Expected severity to be any of the following: [{SEVERITY_TYPES!s}], got [{severity}] instead.",
                )
        except Exception as e:
            return self.default_severity, e

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
                and outputs_display_names[each_destination].destination_id not in standardized_destinations
            ):
                standardized_destinations.append(outputs_display_names[each_destination].destination_id)
            # case for valid UUIDv4
            elif each_destination in outputs and each_destination not in standardized_destinations:
                standardized_destinations.append(each_destination)
            else:
                invalid_destinations.append(each_destination)

        if len(standardized_destinations) > MAX_DESTINATIONS_SIZE:
            # If generated field exceeds max size, truncate it
            standardized_destinations = standardized_destinations[:MAX_DESTINATIONS_SIZE]

        if invalid_destinations:
            try:
                # raise to get a stack trace
                raise UnknownDestinationError("Invalid Destinations", invalid_destinations)
            except UnknownDestinationError as e:
                return standardized_destinations, e

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
                f"detection [{self.id}] method [{method_name}] returned [{type(value).__name__}], expected [{typ.__name__}]",
            )

    def _require_str_list(self, method_name: str, value: Any):
        if value is None:
            return
        if not isinstance(value, list) or not all(isinstance(x, (str, bool)) for x in value):
            raise FunctionReturnTypeError(
                f"detection [{self.id}] method [{method_name}] returned [{type(value).__name__}], expected a list",
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


def panther_managed(cls: Type[Rule]) -> Type[Rule]:
    """Decorator to apply to OOTB rules written by Panther."""
    cls._tests = cls.tests  # type: ignore
    cls.tests = []
    cls._panther_managed = True  # type: ignore
    return cls
