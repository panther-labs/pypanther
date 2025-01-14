"""
Panther Analysis Tool is a command line interface for writing,
testing, and packaging policies/rules.
Copyright (C) 2020 Panther Labs Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import datetime
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Generic, List, Optional, TypeVar

import dateutil.parser

ResponseData = TypeVar("ResponseData")


class BackendError(Exception):
    permanent: bool = False


class PermanentBackendError(BackendError):
    permanent: bool = True


class UnsupportedEndpointError(Exception):
    pass


@dataclass(frozen=True)
class BackendResponse(Generic[ResponseData]):
    data: ResponseData
    status_code: int


@dataclass(frozen=True)
class BackendCheckResponse:
    success: bool
    message: str


@dataclass(frozen=True)
class BulkUploadPresignedURLParams:
    pypanther_version: str


@dataclass(frozen=True)
class BulkUploadPresignedURLResponse:
    detections_url: str
    session_id: str


@dataclass(frozen=True)
class BulkUploadDetectionsParams:
    session_id: str
    dry_run: bool


@dataclass(frozen=True)
class BulkUploadDetectionsResponse:
    job_id: str


@dataclass(frozen=True)
class BulkUploadDetectionsStatusParams:
    job_id: str


@dataclass
class BulkUploadDetectionsError:
    error: str

    @classmethod
    def from_json(cls, data: str) -> "BulkUploadDetectionsError":
        return BulkUploadDetectionsError.from_dict(json.loads(data))

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "BulkUploadDetectionsError":
        if not data:
            return cls(error="")
        err = data.get("errorMessage") or ""
        return cls(error=err)

    def asdict(self) -> dict[str, Any]:
        return {
            "error": self.error,
        }


@dataclass(frozen=True)
class BulkUploadDetectionsResults:
    new_rule_ids: list[str]
    modified_rule_ids: list[str]
    deleted_rule_ids: list[str]
    total_rule_ids: list[str]


@dataclass(frozen=True)
class BulkUploadDetectionsStatusResponse:
    message: str
    status: str
    results: BulkUploadDetectionsResults | None


@dataclass(frozen=True)
class ListSchemasParams:
    is_managed: bool


@dataclass(frozen=True)
class UpdateSchemaParams:
    description: str
    name: str
    reference_url: str
    revision: int
    spec: str
    field_discovery_enabled: bool


# pylint: disable=too-many-instance-attributes
@dataclass()
class Schema:
    created_at: str
    description: str
    is_managed: bool
    name: str
    reference_url: str
    revision: int
    spec: str
    updated_at: str
    field_discovery_enabled: bool


@dataclass(frozen=True)
class ListSchemasResponse:
    schemas: List[Schema]


@dataclass(frozen=True)
class UpdateSchemaResponse:
    schema: Schema


class Client(ABC):
    @abstractmethod
    def check(self) -> BackendCheckResponse:
        pass

    @abstractmethod
    def bulk_upload_presigned_url(
        self,
        params: BulkUploadPresignedURLParams,
    ) -> BackendResponse[BulkUploadPresignedURLResponse]:
        pass

    @abstractmethod
    def bulk_upload_detections(
        self,
        params: BulkUploadDetectionsParams,
    ) -> BackendResponse[BulkUploadDetectionsResponse]:
        pass

    @abstractmethod
    def bulk_upload_detections_status(
        self,
        params: BulkUploadDetectionsStatusParams,
    ) -> BackendResponse[BulkUploadDetectionsStatusResponse]:
        pass

    @abstractmethod
    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[ListSchemasResponse]:
        pass

    @abstractmethod
    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:
        pass


def backend_response_failed(resp: BackendResponse) -> bool:
    return resp.status_code >= 400 or resp.data.get("statusCode", 0) >= 400


def parse_optional_time(time: Optional[str]) -> Optional[datetime.datetime]:
    return None if time is None else dateutil.parser.parse(time)
