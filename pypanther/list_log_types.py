import argparse
import json
from typing import Tuple, cast

from pypanther import display
from pypanther.backend.client import Schema
from pypanther.display import JSON_INDENT_LEVEL
from pypanther.log_types import LogType as ManagedLogType
from pypanther.schemas import Manager as SchemaManager


def run(args: argparse.Namespace) -> Tuple[int, str]:
    log_types = []

    manager = SchemaManager(args)
    local_custom_schemas = manager.schemas
    for schema in local_custom_schemas:
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
