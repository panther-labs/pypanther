import argparse
import json
from typing import Any, Tuple, cast

from pypanther import display, schemas
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
    ListSchemasResponse,
    Schema,
    UpdateSchemaParams,
)
from pypanther.backend.client import Client as BackendClient
from pypanther.display import JSON_INDENT_LEVEL
from pypanther.log_types import LogType as ManagedLogType


# oof
class StubbedClient:
    def check(self) -> BackendCheckResponse:
        raise Exception("Should not be called")

    def bulk_upload_presigned_url(
        self,
        params: BulkUploadPresignedURLParams,
    ) -> BackendResponse[BulkUploadPresignedURLResponse]:
        raise Exception("Should not be called")

    def bulk_upload_detections(
        self,
        params: BulkUploadDetectionsParams,
    ) -> BackendResponse[BulkUploadDetectionsResponse]:
        raise Exception("Should not be called")

    def bulk_upload_detections_status(
        self,
        params: BulkUploadDetectionsStatusParams,
    ) -> BackendResponse[BulkUploadDetectionsStatusResponse]:
        raise Exception("Should not be called")

    def list_schemas(self, params: ListSchemasParams) -> BackendResponse[ListSchemasResponse]:
        raise Exception("Should not be called")

    def update_schema(self, params: UpdateSchemaParams) -> BackendResponse[Any]:
        raise Exception("Should not be called")


def run(args: argparse.Namespace) -> Tuple[int, str]:
    log_types = []
    client = cast(BackendClient, StubbedClient())

    # These are the default values some underlying code needs
    args.dry_run = False
    args.verbose = False

    schema_objects, absolute_path = schemas.prepare(client, args, False)
    for schema in schema_objects:
        if schema.error:
            return 1, schema.error
        local_schema = cast(Schema, schema.schema)
        if args.substring is None or args.substring.lower() in local_schema.name.lower():
            log_types.append(local_schema.name)

    if not args.custom_only:
        for log_type in ManagedLogType:
            if args.substring is None or args.substring.lower() in log_type.lower():
                log_types.append(log_type)

    if args.output == display.OUTPUT_TYPE_TEXT:
        print("\n".join(log_types))
    if args.output == display.OUTPUT_TYPE_JSON:
        print(json.dumps(log_types, indent=JSON_INDENT_LEVEL))

    return 0, ""
