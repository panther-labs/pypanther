import argparse
import logging
import os
import tempfile
import time
import zipfile
from fnmatch import fnmatch
from typing import Optional, Tuple, Any

from pypanther import testing, cli_output
from pypanther.registry import registered_rules
from pypanther.vendor.panther_analysis_tool.backend.client import (
    BackendError,
    BulkUploadMultipartError,
    AsyncBulkUploadParams,
    AsyncBulkUploadStatusParams,
)
from pypanther.vendor.panther_analysis_tool.backend.client import Client as BackendClient
from pypanther.vendor.panther_analysis_tool.util import convert_unicode

INDENT = " " * 2
IGNORE_FOLDERS = [
    ".mypy_cache",
    "pypanther",
    "panther_analysis",
    ".git",
    "__pycache__",
    "tests",
]


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    if not args.confirm:
        err = confirm()
        if err is not None:
            return 0, err

    if not args.skip_tests:
        code, err = testing.run(args)
        if code > 0:
            return code, err

    if args.verbose:
        # main.py imported during testing.run
        print(cli_output.header("Registered Rules"))
        for i, rule in enumerate(registered_rules(), start=1):
            print(INDENT, f"{i}. {rule.id}")
        print()  # new line

    with tempfile.NamedTemporaryFile() as tmp:
        zip_contents(tmp, args.verbose)
        return upload_zip(backend, archive=tmp.name, verbose=args.verbose, max_retries=args.max_retries)


def zip_contents(named_temp_file: Any, verbose: bool):
    with zipfile.ZipFile(named_temp_file, "w") as zip_out:
        for root, dir_, files in os.walk("."):
            for bad in IGNORE_FOLDERS:
                if bad in dir_:
                    dir_.remove(bad)

            for file in files:
                if not fnmatch(file, "*.py"):
                    continue

                filepath = os.path.join(root, file)

                zip_out.write(
                    filepath,
                    arcname=filepath,
                )

        if verbose:
            print(cli_output.header("Included files:"))
            for info in zip_out.infolist():
                print(INDENT, f"- {info.filename}")
            print()  # new line


def upload_zip(backend: BackendClient, archive: str, verbose: bool, max_retries: int = 10) -> Tuple[int, str]:
    # extract max retries we should handle
    # _max_retries = 10
    if max_retries > 10:
        logging.warning("max_retries cannot be greater than 10, defaulting to 10")
        max_retries = 10
    elif max_retries < 0:
        logging.warning("max_retries cannot be negative, defaulting to 0")
        max_retries = 0

    with open(archive, "rb") as analysis_zip:
        if verbose:
            print(cli_output.header("Uploading to Panther"))
        else:
            print("Uploading to Panther")

        upload_params = AsyncBulkUploadParams(zip_bytes=analysis_zip.read())
        retry_count = 0

        while True:
            try:
                start_upload_response = backend.async_bulk_upload(upload_params)
                if verbose:
                    print(INDENT, "- Upload started")

                while True:
                    time.sleep(2)

                    status_response = backend.async_bulk_upload_status(
                        AsyncBulkUploadStatusParams(receipt_id=start_upload_response.data.receipt_id)
                    )
                    if not status_response.data.empty():
                        # resp_dict = asdict(response.data)

                        if verbose:
                            print(INDENT, "- Upload finished")
                            print()  # new line
                            print(cli_output.header("Upload Statistics"))
                            print(INDENT, cli_output.bold("Rules:"))
                            print(INDENT * 2, f"New:     {status_response.data.rules.new}")
                            print(INDENT * 2, f"Modified: {status_response.data.rules.modified}")
                            print(INDENT * 2, f"Deleted: {status_response.data.rules.deleted}")
                            print(INDENT * 2, f"Total:   {status_response.data.rules.total}")
                            print()  # new line

                        print(cli_output.success("Upload succeeded"))
                        return 0, ""

                    if verbose:
                        print(INDENT, "- Upload still in progress")

            except BackendError as be_err:
                err = cli_output.multipart_error_msg(
                    BulkUploadMultipartError.from_jsons(convert_unicode(be_err)),
                    "Upload failed",
                )
                if be_err.permanent is True:
                    return 1, f"Failed to upload to Panther: {err}"

                if max_retries - retry_count > 0:
                    logging.debug("Failed to upload to Panther: %s.", err)
                    retry_count += 1

                    # typical bulk upload takes 30 seconds, allow any currently running one to complete
                    logging.debug(
                        "Will retry upload in 30 seconds. Retries remaining: %s",
                        max_retries - retry_count,
                    )
                    time.sleep(30)

                else:
                    logging.warning("Exhausted retries attempting to perform bulk upload.")
                    return 1, f"Failed to upload to Panther: {err}"

            # PEP8 guide states it is OK to catch BaseException if you log it.
            except BaseException as err:  # pylint: disable=broad-except
                return 1, f"Failed to upload to Panther: {err}"


def confirm() -> Optional[str]:
    warning_text = cli_output.warning(
        "WARNING: pypanther upload is under active development and not recommended for use"
        " without guidance from the Panther team. Would you like to proceed? [y/n]: "
    )
    choice = input(warning_text).lower()
    if choice != "y":
        print(cli_output.warning(f'Exiting upload due to entered response "{choice}" which is not "y"'))
        return "User did not confirm"
    return None
