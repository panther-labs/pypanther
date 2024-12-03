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
    def bulk_upload_presigned_url(  # type: ignore
        self,
        params: BulkUploadPresignedURLParams,
    ) -> BackendResponse[BulkUploadPresignedURLResponse]:  # type: ignore
        pass

    def bulk_upload_detections(  # type: ignore
        self,
        params: BulkUploadDetectionsParams,
    ) -> BackendResponse[BulkUploadDetectionsResponse]:
        pass

    def bulk_upload_detections_status(  # type: ignore
        self,
        params: BulkUploadDetectionsStatusParams,
    ) -> BackendResponse[BulkUploadDetectionsStatusResponse]:
        pass

    def check(self) -> BackendCheckResponse:  # type: ignore
        pass

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[Any]:  # type: ignore
        pass

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:  # type: ignore
        pass
