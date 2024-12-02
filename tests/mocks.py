from typing import Any

from pypanther.backend.client import (
    AsyncBulkUploadParams,
    AsyncBulkUploadResponse,
    AsyncBulkUploadStatusParams,
    AsyncBulkUploadStatusResponse,
    BackendCheckResponse,
    BackendResponse,
    ListSchemasParams,
    UpdateSchemaParams,
)
from pypanther.backend.client import (
    Client as BackendClient,
)


class MockBackend(BackendClient):
    def async_bulk_upload(self, params: AsyncBulkUploadParams) -> BackendResponse[AsyncBulkUploadResponse]:  # type: ignore
        pass

    def async_bulk_upload_status(
        self,
        params: AsyncBulkUploadStatusParams,
    ) -> BackendResponse[AsyncBulkUploadStatusResponse] | None:  # type: ignore
        pass

    def check(self) -> BackendCheckResponse:  # type: ignore
        pass

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:  # type: ignore
        pass
