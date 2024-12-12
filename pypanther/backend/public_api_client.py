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

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import urlparse

from .errors import is_retryable_error

if TYPE_CHECKING:
    # defer loading to improve performance
    from gql import Client as GraphQLClient
    from graphql import DocumentNode, ExecutionResult

from gql.transport.exceptions import TransportQueryError

from pypanther import display

from .client import (
    BackendCheckResponse,
    BackendError,
    BackendResponse,
    BulkUploadDetectionsParams,
    BulkUploadDetectionsResponse,
    BulkUploadDetectionsResults,
    BulkUploadDetectionsStatusParams,
    BulkUploadDetectionsStatusResponse,
    BulkUploadPresignedURLParams,
    BulkUploadPresignedURLResponse,
    Client,
    ListSchemasParams,
    ListSchemasResponse,
    PermanentBackendError,
    Schema,
    UpdateSchemaParams,
    UpdateSchemaResponse,
)


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

    def bulk_upload_presigned_url_query(self) -> "DocumentNode":
        return self._load("bulk_upload_presigned_url")

    def bulk_upload_detections_mutation(self) -> "DocumentNode":
        return self._load("bulk_upload_detections")

    def bulk_upload_detections_status_query(self) -> "DocumentNode":
        return self._load("bulk_upload_detections_status")

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

    def bulk_upload_presigned_url(
        self,
        params: BulkUploadPresignedURLParams,
    ) -> BackendResponse[BulkUploadPresignedURLResponse]:
        query = self._requests.bulk_upload_presigned_url_query()
        request_params = {
            "input": {
                "pypantherVersion": params.pypanther_version,
            },
        }
        response = self._safe_execute(query, variable_values=request_params)
        url = response.data.get("bulkUploadPresignedUrl", {}).get("detectionsURL")  # type: ignore
        session_id = response.data.get("bulkUploadPresignedUrl", {}).get("sessionId")  # type: ignore
        return BackendResponse(
            status_code=200,
            data=BulkUploadPresignedURLResponse(
                detections_url=url,
                session_id=session_id,
            ),
        )

    def bulk_upload_detections(
        self,
        params: BulkUploadDetectionsParams,
    ) -> BackendResponse[BulkUploadDetectionsResponse]:
        query = self._requests.bulk_upload_detections_mutation()
        upload_params = {
            "input": {
                "dryRun": params.dry_run,
                "sessionId": params.session_id,
            },
        }
        res = self._safe_execute(query, variable_values=upload_params)
        job_id = res.data.get("bulkUploadDetections", {}).get("id")  # type: ignore
        return BackendResponse(
            status_code=200,
            data=BulkUploadDetectionsResponse(job_id=job_id),
        )

    def bulk_upload_detections_status(
        self,
        params: BulkUploadDetectionsStatusParams,
    ) -> BackendResponse[BulkUploadDetectionsStatusResponse]:
        query = self._requests.bulk_upload_detections_status_query()
        upload_params = {"input": params.job_id}
        res = self._safe_execute(query, variable_values=upload_params).data.get("bulkUploadDetectionsStatus", {})  # type: ignore
        results = None
        if res_results := res.get("results"):
            results = BulkUploadDetectionsResults(
                new_rule_ids=res_results.get("newRuleIds") or [],
                modified_rule_ids=res_results.get("modifiedRuleIds") or [],
                deleted_rule_ids=res_results.get("deletedRuleIds") or [],
                total_rule_ids=res_results.get("totalRuleIds") or [],
            )

        return BackendResponse(
            status_code=200,
            data=BulkUploadDetectionsStatusResponse(
                status=res.get("status"),
                message=res.get("message"),
                results=results,
            ),
        )

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
