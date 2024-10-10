import ast
import enum
from typing import Any, Literal, Self

from pydantic import BaseModel, Field, model_validator

from pypanther.log_types import LogType
from pypanther.severity import Severity


class PythonModule(BaseModel):
    name: str
    code: ast.Module

    class Config:  # noqa: D106
        # this is needed so that pydantic allows us to use ast.Module
        arbitrary_types_allowed = True


class PythonPackage(BaseModel):
    name: str
    init_code: ast.Module | None = Field(None)
    subpackages: list["PythonPackage"]
    modules: list[PythonModule]

    class Config:  # noqa: D106
        # this is needed so that pydantic allows us to use ast.Module (in PythonModule)
        arbitrary_types_allowed = True


class AnalysisType(enum.Enum):
    GLOBAL = "global"
    DATAMODEL = "datamodel"
    RULE = "rule"
    SCHEDULED_RULE = "scheduled_rule"


class V1HelperMetadata(BaseModel):
    analysis_type: AnalysisType = Field(alias="AnalysisType")
    filename: str = Field(alias="Filename", pattern=r"^\w+\.py$")


class V1Helper(BaseModel):
    metadata: V1HelperMetadata
    module: PythonModule

    @model_validator(mode="after")
    def check_filename_and_module_name_match(self: Self) -> Self:
        if self.metadata.filename.removesuffix(".py") != self.module.name:
            msg = "module.name and filename should match"
            raise ValueError(msg)
        return self


class Mapping(BaseModel):
    name: str = Field(alias="Name")
    path: str | None = Field(None, alias="Path")
    method: str | None = Field(None, alias="Method")

    @model_validator(mode="after")
    def check_exactly_one_of_path_or_method_is_set(self: Self) -> Self:
        if self.path and self.method:
            msg = "only one of path and method must be set"
            raise ValueError(msg)
        return self


class V1DataModelMetadata(BaseModel):
    analysis_type: AnalysisType = Field(alias="AnalysisType")
    data_model_id: str = Field(alias="DataModelID")
    display_name: str | None = Field(None, alias="DisplayName")
    enabled: bool = Field(alias="Enabled")
    filename: str = Field(alias="Filename", pattern=r"^\w+\.py$")
    # TODO: add better validation for this
    log_types: list[str] = Field(alias="LogTypes")
    mappings: list[Mapping] = Field(alias="Mappings")


class V1DataModel(BaseModel):
    metadata: V1DataModelMetadata
    module: PythonModule

    @model_validator(mode="after")
    def check_filename_and_module_name_match(self: Self) -> Self:
        if self.metadata.filename.removesuffix(".py") != self.module.name:
            msg = "module.name and filename should match"
            raise ValueError(msg)
        return self


class Mock(BaseModel):
    object_name: str = Field(alias="objectName")
    return_value: str = Field(alias="returnValue")

    @model_validator(mode="before")
    @classmethod
    def convert_return_value_to_string(cls: type[Self], data: dict[str, Any]) -> dict[str, Any]:
        data["returnValue"] = str(data["returnValue"])
        return data


class Test(BaseModel):
    name: str = Field(alias="Name")
    expected_result: bool = Field(alias="ExpectedResult")
    log: dict[str, Any] = Field(alias="Log")
    mocks: list[Mock] | None = Field(None, alias="Mocks")

    @model_validator(mode="after")
    def filter_out_filter_include_event_from_mocks(self: Self) -> Self:
        if not self.mocks:
            return self
        self.mocks = [m for m in self.mocks if m.object_name != "filter_include_event"]
        return self


class V1RuleMetadata(BaseModel):
    analysis_type: AnalysisType = Field(alias="AnalysisType")
    filename: str = Field(alias="Filename")
    rule_id: str = Field(alias="RuleID")
    display_name: str = Field(alias="DisplayName")
    enabled: bool = Field(alias="Enabled")
    log_types: list[LogType] = Field(alias="LogTypes")
    tags: list[str] | None = Field(None, alias="Tags")
    reports: dict[Literal["Panther", "MITRE ATT&CK", "CIS", "TA0004", "GCP_CIS_1.3"], list[str]] | None = Field(
        None, alias="Reports",
    )
    severity: Severity = Field(alias="Severity")
    create_alert: bool | None = Field(None, alias="CreateAlert")
    description: str | None = Field(None, alias="Description")
    reference: str | None = Field(None, alias="Reference")
    runbook: str | None = Field(None, alias="Runbook")
    summary_attributes: list[str] | None = Field(None, alias="SummaryAttributes")
    tests: list[Test] | None = Field(None, alias="Tests")
    # detection is not implemented
    # detection: Any = Field(None, alias="Detection")

    @model_validator(mode="before")
    @classmethod
    def convert_severity_to_enum(cls: type[Self], data: dict[str, Any]) -> dict[str, Any]:
        data["Severity"] = Severity(data["Severity"].upper())
        if "Reports" in data:
            data["Reports"] = {k: [str(y) for y in v] for k, v in data["Reports"].items()}
        return data


class V1Rule(BaseModel):
    metadata: V1RuleMetadata
    module: PythonModule

    @model_validator(mode="after")
    def check_filename_and_module_name_match(self: Self) -> Self:
        if self.metadata.filename.removesuffix(".py") != self.module.name:
            msg = "module.name and filename should match"
            raise ValueError(msg)
        return self
