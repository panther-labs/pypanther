import argparse
import json
from typing import Tuple

from pypanther import display
from pypanther.display import JSON_INDENT_LEVEL
from pypanther.log_types import LogType


def run(args: argparse.Namespace) -> Tuple[int, str]:
    log_types = []
    for log_type in LogType:
        if args.substring is None or args.substring.lower() in log_type.lower():
            log_types.append(log_type)

    if args.output == display.OUTPUT_TYPE_TEXT:
        print("\n".join(log_types))
    if args.output == display.OUTPUT_TYPE_JSON:
        print(json.dumps(log_types, indent=JSON_INDENT_LEVEL))

    return 0, ""
