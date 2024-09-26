import ast
import enum
from typing import Any, Self

from pydantic import BaseModel, Field, field_validator, model_validator


class PythonModule(BaseModel):
    name: str
    code: ast.Module


class PythonPackage(BaseModel):
    name: str
    init_code: ast.Module | None = Field(None)
    subpackages: list["PythonPackage"]
    modules: list[PythonModule]


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
