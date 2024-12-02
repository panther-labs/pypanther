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

import importlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import urlparse

if TYPE_CHECKING:
    # defer loading to improve performance
    from gql import Client as GraphQLClient
    from graphql import DocumentNode, ExecutionResult

from pypanther import display

from .client import (
    AsyncBulkUploadParams,
    AsyncBulkUploadResponse,
    AsyncBulkUploadStatusParams,
    AsyncBulkUploadStatusResponse,
    BackendCheckResponse,
    BackendError,
    BackendResponse,
    Client,
    ListSchemasParams,
    ListSchemasResponse,
    PermanentBackendError,
    Schema,
    UnsupportedEndpointError,
    UpdateSchemaParams,
    UpdateSchemaResponse,
    to_bulk_upload_statistics,
)
from .errors import is_retryable_error, is_retryable_error_str

BULK_UPLOAD_MODE_V2_ZIP = "V2_ZIP"


@dataclass(frozen=True)
class PublicAPIClientOptions:
    host: str
    token: str
    user_id: str
    verbose: bool
    output_type: str


class PublicAPIRequests:  # pylint: disable=too-many-public-methods
    _cache: Dict[str, str]

    def __init__(self) -> None:
        self._cache = {}

    def version_query(self) -> "DocumentNode":
        return self._load("get_version")

    def async_bulk_upload_mutation(self) -> "DocumentNode":
        return self._load("async_bulk_upload")

    def async_bulk_upload_status_query(self) -> "DocumentNode":
        return self._load("async_bulk_upload_status")

    def list_schemas_query(self) -> "DocumentNode":
        return self._load("list_schemas")

    def update_schema_mutation(self) -> "DocumentNode":
        return self._load("create_or_update_schema")

    def _load(self, name: str) -> "DocumentNode":
        # defer loading to improve performance
        from gql import gql

        if name not in self._cache:
            self._cache[name] = Path(_get_graphql_content_filepath(name)).read_text(encoding="utf-8")

        return gql(self._cache[name])


class PublicAPIClient(Client):  # pylint: disable=too-many-public-methods
    _user_id: str
    _requests: PublicAPIRequests
    _gql_client: "GraphQLClient"

    def __init__(self, opts: PublicAPIClientOptions):
        self._user_id = opts.user_id
        self._requests = PublicAPIRequests()
        self._gql_client = _build_client(opts.host, opts.token, opts.verbose, opts.output_type)

    def check(self) -> BackendCheckResponse:
        res = self._execute(self._requests.version_query())

        if res.errors:
            for err in res.errors:
                logging.error(err.message)

            return BackendCheckResponse(success=False, message="connection check failed")

        if res.data is None:
            return BackendCheckResponse(success=False, message="backend sent empty response")

        panther_version = res.data.get("generalSettings", {}).get("pantherVersion")
        if panther_version is None:
            return BackendCheckResponse(
                success=False,
                message="did not receive version in response",
            )

        return BackendCheckResponse(success=True, message=f"connected to Panther backend on version: {panther_version}")

    def async_bulk_upload(self, params: AsyncBulkUploadParams) -> BackendResponse[AsyncBulkUploadResponse]:
        query = self._requests.async_bulk_upload_mutation()
        upload_params = {
            "input": {
                "data": params.encoded_bytes(),
                "pypantherVersion": importlib.metadata.version("pypanther"),
                "mode": BULK_UPLOAD_MODE_V2_ZIP,
                "dryRun": params.dry_run,
            },
        }
        res = self._safe_execute(query, variable_values=upload_params)
        receipt_id = res.data.get("uploadDetectionEntitiesAsync", {}).get("receiptId")  # type: ignore
        if not receipt_id:
            raise BackendError("empty data")

        return BackendResponse(
            status_code=200,
            data=AsyncBulkUploadResponse(receipt_id=receipt_id),
        )

    def async_bulk_upload_status(
        self,
        params: AsyncBulkUploadStatusParams,
    ) -> BackendResponse[AsyncBulkUploadStatusResponse] | None:
        query = self._requests.async_bulk_upload_status_query()
        params = {"input": params.receipt_id}  # type: ignore
        res = self._safe_execute(query, variable_values=params)  # type: ignore
        result = res.data.get("detectionEntitiesUploadStatus", {})  # type: ignore
        status = result.get("status", "")
        error = result.get("error")
        data = result.get("result")

        if status == "FAILED":
            if is_retryable_error_str(error):
                raise BackendError(error)
            raise PermanentBackendError(error)

        if status == "COMPLETED":
            return to_bulk_upload_statistics(data)

        if status not in ["NOT_PROCESSED"]:
            raise BackendError(f"unexpected status: {status}")

        return None

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[ListSchemasResponse]:
        gql_params = {
            "input": {
                "isManaged": params.is_managed,
            },
        }
        res = self._execute(self._requests.list_schemas_query(), gql_params)
        if res.errors:
            for err in res.errors:
                logging.error(err.message)
            raise BackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        schemas = []
        for edge in res.data.get("schemas", {}).get("edges", []):
            node = edge.get("node", {})
            schema = Schema(
                created_at=node.get("createdAt", ""),
                description=node.get("description", ""),
                is_managed=node.get("isManaged", False),
                name=node.get("name", ""),
                reference_url=node.get("referenceURL", ""),
                revision=node.get("revision", ""),
                spec=node.get("spec", ""),
                updated_at=node.get("updatedAt", ""),
                field_discovery_enabled=node.get("fieldDiscoveryEnabled", False),
            )
            schemas.append(schema)

        return BackendResponse(status_code=200, data=ListSchemasResponse(schemas=schemas))

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse:
        from gql.transport.exceptions import TransportQueryError

        gql_params = {
            "input": {
                "description": params.description,
                "name": params.name,
                "referenceURL": params.reference_url,
                "revision": params.revision,
                "spec": params.spec,
                "isFieldDiscoveryEnabled": params.field_discovery_enabled,
            },
        }
        try:
            res = self._execute(self._requests.update_schema_mutation(), gql_params)
            if res.errors:
                for err in res.errors:
                    logging.error(err.message)
                raise BackendError(res.errors)
        except TransportQueryError as exc:
            raise BackendError(exc)

        if res.data is None:
            raise BackendError("empty data")

        schema = res.data.get("schema", {})
        return BackendResponse(
            status_code=200,
            data=UpdateSchemaResponse(
                schema=Schema(
                    created_at=schema.get("createdAt", ""),
                    description=schema.get("description", ""),
                    is_managed=schema.get("isManaged", False),
                    name=schema.get("name", ""),
                    reference_url=schema.get("referenceURL", ""),
                    revision=schema.get("revision", ""),
                    spec=schema.get("spec", ""),
                    updated_at=schema.get("updatedAt", ""),
                    field_discovery_enabled=schema.get("fieldDiscoveryEnabled", False),
                ),
            ),
        )

    def _execute(
        self,
        request: "DocumentNode",
        variable_values: Optional[Dict[str, Any]] = None,
    ) -> "ExecutionResult":
        return self._gql_client.execute(request, variable_values=variable_values, get_execution_result=True)

    def _safe_execute(
        self,
        request: "DocumentNode",
        variable_values: Optional[Dict[str, Any]] = None,
    ) -> "ExecutionResult":
        # defer loading to improve performance
        from gql.transport.exceptions import TransportQueryError

        try:
            res = self._execute(request, variable_values=variable_values)
        except TransportQueryError as e:  # pylint: disable=C0103
            err = PermanentBackendError(e)
            if e.errors and len(e.errors) > 0:
                err = BackendError(e.errors[0])  # type: ignore
                err.permanent = not is_retryable_error(e.errors[0])
            raise err from e

        if res.errors:
            raise PermanentBackendError(res.errors)

        if res.data is None:
            raise BackendError("empty data")

        return res

    def _potentially_supported_execute(
        self,
        request: "DocumentNode",
        variable_values: Optional[Dict[str, Any]] = None,
    ) -> "ExecutionResult":
        """
        Same behavior as _safe_execute but throws an UnSupportedEndpointError
        whenever a graphql validation error is detected
        """
        try:
            return self._safe_execute(request, variable_values)
        except BaseException as err:
            not_supported = False
            try:
                not_supported = (
                    err.args[0]["extensions"]["code"]  # pylint: disable=invalid-sequence-index
                    == "GRAPHQL_VALIDATION_FAILED"
                )
            except BaseException:  # pylint: disable=broad-except
                pass

            if not_supported:
                raise UnsupportedEndpointError(err) from err

            raise err


_API_URL_PATH = "public/graphql"
_API_DOMAIN_PREFIX = "api"
_API_TOKEN_HEADER = "X-API-Key"  # nosec


def _build_client(host: str, token: str, verbose: bool, output_type: str = display.OUTPUT_TYPE_TEXT) -> "GraphQLClient":
    from gql import Client as GraphQLClient
    from gql.transport.aiohttp import AIOHTTPTransport

    graphql_url = _build_api_url(host)
    if verbose and output_type == display.OUTPUT_TYPE_TEXT:
        print("Panther Public API endpoint: %s", graphql_url)
        print()  # new line

    transport = AIOHTTPTransport(url=graphql_url, headers={_API_TOKEN_HEADER: token})

    return GraphQLClient(transport=transport, fetch_schema_from_transport=False, execute_timeout=30)


def is_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def _build_api_url(host: str) -> str:
    if is_url(host):
        return host

    return f"https://{_API_DOMAIN_PREFIX}.{host}/{_API_URL_PATH}"


def _get_graphql_content_filepath(name: str) -> str:
    work_dir = os.path.dirname(__file__)
    return os.path.join(work_dir, "graphql", f"{name}.graphql")
