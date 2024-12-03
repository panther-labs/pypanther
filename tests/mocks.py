from typing import Any

from pypanther.backend.client import (
    BackendCheckResponse,
    BackendResponse,
    BulkUploadDetectionsParams,
    BulkUploadDetectionsResponse,
    BulkUploadDetectionsStatusParams,
    BulkUploadDetectionsStatusResponse,
    BulkUploadPresignedURLParams,
    BulkUploadPresignedURLResponse,
    ListSchemasParams,
    UpdateSchemaParams,
)
from pypanther.backend.client import (
    Client as BackendClient,
)


class MockBackend(BackendClient):
    def bulk_upload_presigned_url(
        self,
        params: BulkUploadPresignedURLParams,
    ) -> BackendResponse[BulkUploadPresignedURLResponse] | None:  # type: ignore
        pass

    def bulk_upload_detections(
        self,
        params: BulkUploadDetectionsParams,
    ) -> BackendResponse[BulkUploadDetectionsResponse] | None:  # type: ignore
        pass

    def bulk_upload_detections_status(
        self,
        params: BulkUploadDetectionsStatusParams,
    ) -> BackendResponse[BulkUploadDetectionsStatusResponse] | None:  # type: ignore
        pass

    def check(self) -> BackendCheckResponse:  # type: ignore
        pass

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:  # type: ignore
        pass
