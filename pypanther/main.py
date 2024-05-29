import argparse
import importlib

from pypanther.upload import run as upload
from pypanther.vendor.panther_analysis_tool import util
from pypanther.vendor.panther_analysis_tool.command import standard_args
from pypanther.vendor.panther_analysis_tool.config import dynaconf_argparse_merge, setup_dynaconf


def run():
    parser = argparse.ArgumentParser(description="Command line tool for uploading files.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a file")

    standard_args.for_public_api(upload_parser, required=False)
    upload_parser.set_defaults(func=util.func_with_backend(upload))
    upload_parser.add_argument(
        "--max-retries",
        help="Retry to upload on a failure for a maximum number of times",
        default=10,
        type=int,
        required=False,
    )

    # Version command
    version_parser = subparsers.add_parser("version", help="version")
    version_parser.set_defaults(func=version)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    config_file_settings = setup_dynaconf()
    dynaconf_argparse_merge(vars(args), config_file_settings)

    args.func(args)


def version(args):
    print(importlib.metadata.version("pypanther"))
