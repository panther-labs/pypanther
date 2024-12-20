import argparse
import json
from typing import Tuple

from pypanther import display, schemas
from pypanther.display import JSON_INDENT_LEVEL
from pypanther.log_types import LogType as ManagedLogType


def run(args: argparse.Namespace) -> Tuple[int, str]:
    log_types = []

    manager = schemas.Manager(args.schemas_path, verbose=False, dry_run=False)
    local_custom_schemas = manager.schemas
    for schema in local_custom_schemas:
        if schema.error:
            return 1, schema.error
        if schema.schema is None:
            raise ValueError("Schema is None")
        if args.substring is None or args.substring.lower() in schema.schema.name.lower():
            log_types.append(schema.schema.name)

    if not args.custom_only:
        for log_type in ManagedLogType:
            if args.substring is None or args.substring.lower() in log_type.lower():
                log_types.append(log_type)

    if args.output == display.OUTPUT_TYPE_TEXT:
        print("\n".join(log_types))
    if args.output == display.OUTPUT_TYPE_JSON:
        print(json.dumps(log_types, indent=JSON_INDENT_LEVEL))

    return 0, ""
