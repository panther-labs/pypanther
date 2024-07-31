import argparse
import json
import logging
import os
import tempfile
import time
import zipfile
from dataclasses import asdict
from fnmatch import fnmatch
from typing import Optional, Tuple, Any

from pypanther import testing, cli_output, display
from pypanther.import_main import import_main, NoMainModuleError
from pypanther.registry import registered_rules
from pypanther.vendor.panther_analysis_tool.backend.client import (
    BackendError,
    BulkUploadMultipartError,
    AsyncBulkUploadParams,
    AsyncBulkUploadStatusParams,
    AsyncBulkUploadStatusResponse,
    BackendResponse,
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

    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")
        return 1, ""

    test_results = testing.TestResults()  # default to something, so it can be used below in output
    if not args.skip_tests:
        test_results = testing.run_tests(args.verbose, args.output)
        if test_results.had_failed_tests():
            output = get_upload_output_as_dict(None, test_results, [], args.verbose, args.skip_tests)
            print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
            return 1, ""

        if args.output == display.OUTPUT_TYPE_TEXT:
            print()  # new line to separate test output from upload output

    if args.verbose and args.output == display.OUTPUT_TYPE_TEXT:
        print_registered_rules()

    with tempfile.NamedTemporaryFile() as tmp:
        zip_info = zip_contents(tmp)

        if args.verbose and args.output == display.OUTPUT_TYPE_TEXT:
            print_included_files(zip_info)

        try:
            upload_stats = upload_zip(
                backend, archive=tmp.name, verbose=args.verbose, output_type=args.output, max_retries=args.max_retries
            )

            if args.output == display.OUTPUT_TYPE_JSON:
                output = get_upload_output_as_dict(upload_stats, test_results, zip_info, args.verbose, args.skip_tests)
                print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))

        except BackendError as be_err:
            err = BulkUploadMultipartError.from_jsons(convert_unicode(be_err))
            if args.output == display.OUTPUT_TYPE_TEXT:
                print_backend_issues(err)
            elif args.output == display.OUTPUT_TYPE_JSON:
                output = get_failed_upload_as_dict(err, test_results, zip_info, args.verbose, args.skip_tests)
                print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
            return 1, ""

    return 0, ""


def zip_contents(named_temp_file: Any) -> list[zipfile.ZipInfo]:
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

            return zip_out.infolist()


def upload_zip(
    backend: BackendClient, archive: str, verbose: bool, output_type: str, max_retries: int = 10
) -> AsyncBulkUploadStatusResponse:
    # extract max retries we should handle
    # _max_retries = 10
    if max_retries > 10:
        logging.warning("max_retries cannot be greater than 10, defaulting to 10")
        max_retries = 10
    elif max_retries < 0:
        logging.warning("max_retries cannot be negative, defaulting to 0")
        max_retries = 0

    with open(archive, "rb") as analysis_zip:
        if verbose and output_type == display.OUTPUT_TYPE_TEXT:
            print(cli_output.header("Uploading to Panther"))
        elif output_type == display.OUTPUT_TYPE_TEXT:
            print("Uploading to Panther")
            print()  # new line

        upload_params = AsyncBulkUploadParams(zip_bytes=analysis_zip.read())
        retry_count = 0

    while True:
        try:
            start_upload_response = backend.async_bulk_upload(upload_params)
            if verbose and output_type == display.OUTPUT_TYPE_TEXT:
                print(INDENT, "- Upload started")

            while True:
                time.sleep(2)

                status_response = backend.async_bulk_upload_status(
                    AsyncBulkUploadStatusParams(receipt_id=start_upload_response.data.receipt_id)
                )
                if not status_response.data.empty():
                    # resp_dict = asdict(response.data)

                    if output_type == display.OUTPUT_TYPE_TEXT:
                        if verbose:
                            print(INDENT, "- Upload finished")
                            print()  # new line

                        print_upload_statistics(status_response)

                    if output_type == display.OUTPUT_TYPE_TEXT:
                        print(cli_output.success("Upload succeeded"))

                    return status_response.data

                if verbose and output_type == display.OUTPUT_TYPE_TEXT:
                    print(INDENT, "- Upload still in progress")

        except BackendError as be_err:
            if verbose and output_type == display.OUTPUT_TYPE_TEXT:
                print()  # new line for after upload statuses

            if be_err.permanent is True:
                raise be_err

            if max_retries - retry_count > 0:
                retry_count += 1

                if verbose and output_type == display.OUTPUT_TYPE_TEXT:
                    print(INDENT, "- Upload failed")
                    print(INDENT, f"- Will retry in 30 seconds ({max_retries - retry_count} retries remaining)")

                time.sleep(30)

            else:
                logging.warning("Exhausted retries attempting to perform bulk upload.")
                raise be_err

        # PEP8 guide states it is OK to catch BaseException if you log it.
        except BaseException as err:  # pylint: disable=broad-except
            raise err


def confirm() -> Optional[str]:
    warning_text = cli_output.warning(
        "WARNING: pypanther upload is under active development and not recommended for use"
        " without guidance from the Panther team. Would you like to proceed? [y/n]: "
    )
    choice = input(warning_text).lower()
    if choice != "y":
        print(cli_output.warning(f'Exiting upload due to entered response "{choice}" which is not "y"'))
        return "User did not confirm"

    print()  # new line
    return None


def get_upload_output_as_dict(
    upload_stats: AsyncBulkUploadStatusResponse | None,
    test_results: testing.TestResults,
    zip_infos: list[zipfile.ZipInfo],
    verbose: bool,
    skip_tests: bool,
) -> dict:
    output = {}
    if upload_stats is not None:
        output["upload_statistics"] = asdict(upload_stats)
    if not skip_tests:
        output["tests"] = testing.test_output_dict(test_results, verbose)
    if verbose:
        output["registered_rules"] = [rule.id for rule in registered_rules()]
        if len(zip_infos) > 0:
            output["included_files"] = [info.filename for info in zip_infos]

    return output


def get_failed_upload_as_dict(
    err: BulkUploadMultipartError,
    test_results: testing.TestResults,
    zip_infos: list[zipfile.ZipInfo],
    verbose: bool,
    skip_tests: bool,
) -> dict:
    output = {"failed_upload_details": err.asdict()}
    if not skip_tests:
        output["tests"] = testing.test_output_dict(test_results, verbose)
    if verbose:
        output["registered_rules"] = [rule.id for rule in registered_rules()]
        if len(zip_infos) > 0:
            output["included_files"] = [info.filename for info in zip_infos]

    return output


def print_registered_rules() -> None:
    print(cli_output.header("Registered Rules"))
    for i, rule in enumerate(registered_rules(), start=1):
        print(INDENT, f"{i}. {rule.id}")
    print()  # new line


def print_included_files(zip_info: list[zipfile.ZipInfo]) -> None:
    print(cli_output.header("Included files:"))
    for info in zip_info:
        print(INDENT, f"- {info.filename}")
    print()  # new line


def print_upload_statistics(status_response: BackendResponse[AsyncBulkUploadStatusResponse]) -> None:
    print(cli_output.header("Upload Statistics"))
    for category, stats in asdict(status_response.data).items():
        print(INDENT, cli_output.bold(f"{str(category).title()}:"))
        for k, stat in stats.items():
            print(
                INDENT * 2,
                "{:<9} {}".format(str(k).title() + ":", stat),
            )

    print()  # new line


def print_backend_issues(err: BulkUploadMultipartError) -> None:
    print(cli_output.failed("Upload Failed"))
    if err.get_error() != "":
        print(INDENT, f"- {cli_output.failed(err.get_error())}")
    if len(err.get_issues()) > 0:
        for issue in err.get_issues():
            print(INDENT, f"- Error: {cli_output.failed(issue.error_message)}")
            print(INDENT, f"  Path:  {cli_output.failed(issue.path)}")
