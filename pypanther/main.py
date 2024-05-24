import argparse
from typing import Any, Dict

from pypanther.upload import run as upload
from pypanther.vendor.panther_analysis_tool import util
from pypanther.vendor.panther_analysis_tool.command import standard_args


def run():
    parser = argparse.ArgumentParser(description="Command line tool for uploading files.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    no_async_uploads_name = "--no-async"
    no_async_uploads_arg: Dict[str, Any] = {
        "action": "store_true",
        "default": False,
        "required": False,
        "help": "When set your upload will be synchronous",
    }
    standard_args.for_public_api(upload_parser, required=False)
    standard_args.using_aws_profile(upload_parser)
    upload_parser.set_defaults(func=util.func_with_backend(upload))
    upload_parser.add_argument(no_async_uploads_name, **no_async_uploads_arg)
    upload_parser.add_argument(
        "--max-retries",
        help="Retry to upload on a failure for a maximum number of times",
        default=10,
        type=int,
        required=False,
    )

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return
    args.func(args)
