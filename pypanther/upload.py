import argparse
import json
import logging
import os
import tempfile
import time
import zipfile
from dataclasses import asdict
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Optional, Tuple, TypedDict

from pypanther import cli_output, display, testing
from pypanther.backend.client import (
    AsyncBulkUploadParams,
    AsyncBulkUploadStatusParams,
    AsyncBulkUploadStatusResponse,
    BackendError,
    BackendResponse,
    BulkUploadMultipartError,
)
from pypanther.backend.client import Client as BackendClient
from pypanther.backend.util import convert_unicode
from pypanther.import_main import NoMainModuleError, import_main
from pypanther.registry import registered_rules

INDENT = " " * 2
IGNORE_FOLDERS = [
    ".mypy_cache",
    "pypanther",
    "panther_analysis",
    ".git",
    "__pycache__",
    "tests",
    ".venv",
]

UPLOAD_RESULT_SUCCESS = "UPLOAD_SUCCEEDED"
UPLOAD_RESULT_FAILURE = "UPLOAD_FAILED"
UPLOAD_RESULT_TESTS_FAILED = "TESTS_FAILED"

# There are a couple backend limitations that require the size to be this low.
# Lambda has a payload size limit of 6MB.
# The graphql client requires it to be a limit of 4MB (not an exact number).
UPLOAD_SIZE_LIMIT_MB = 4
UPLOAD_SIZE_LIMIT_BYTES = UPLOAD_SIZE_LIMIT_MB * 1024 * 1024


class ChangesSummary(TypedDict):
    message: str
    new: int
    delete: int
    modify: int
    total: int
    new_ids: list[str] | None
    delete_ids: list[str] | None
    modify_ids: list[str] | None
    total_ids: list[str] | None


def run(backend: BackendClient, args: argparse.Namespace) -> Tuple[int, str]:
    if not args.confirm:
        err = confirm(
            "WARNING: pypanther upload is under active development and not recommended for use"
            " without guidance from the Panther team. Would you like to proceed? [y/n]: ",
        )
        if err is not None:
            return 0, ""

    try:
        import_main(os.getcwd(), "main")
    except NoMainModuleError:
        logging.error("No main.py found")  # noqa: TRY400
        return 1, ""

    test_results = testing.TestResults()  # default to something, so it can be used below in output
    if not args.skip_tests:
        test_results = testing.run_tests(args)
        if test_results.had_failed_tests():
            if args.output == display.OUTPUT_TYPE_JSON:
                output = get_upload_output_as_dict(
                    None,
                    test_results,
                    [],
                    args.verbose,
                    args.skip_tests,
                    UPLOAD_RESULT_TESTS_FAILED,
                    None,
                )
                print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
            return 1, ""

        if args.output == display.OUTPUT_TYPE_TEXT:
            print()  # new line to separate test output from upload output

    if args.verbose and args.output == display.OUTPUT_TYPE_TEXT:
        print_registered_rules()

    with tempfile.NamedTemporaryFile() as tmp:
        zip_info = zip_contents(tmp)
        zip_size = Path.stat(Path(tmp.name)).st_size

        if zip_size > UPLOAD_SIZE_LIMIT_BYTES:
            return 1, (
                "Zip file is too big. Reduce number of files or contents of files before "
                f"uploading again (Limit: {UPLOAD_SIZE_LIMIT_MB} MB, Zip size: {zip_size / (1024 * 1024):0.3f} MB)."
            )

        if args.verbose and args.output == display.OUTPUT_TYPE_TEXT:
            print_included_files(zip_info)

        try:
            changes_summary = None
            if not args.skip_summary:
                changes_summary = dry_run_upload(backend, Path(tmp.name).read_bytes(), args.verbose, args.output)

                if args.output == display.OUTPUT_TYPE_JSON:
                    output = get_upload_output_as_dict(
                        None,
                        test_results,
                        [],
                        args.verbose,
                        args.skip_tests,
                        UPLOAD_RESULT_TESTS_FAILED,
                        changes_summary,
                    )
                    print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
                else:
                    print_changes_summary(changes_summary)

            if args.dry_run:
                return 0, ""

            if not args.skip_summary and not args.confirm:
                # if the user skips calculating the summary of the changes,
                # "--confirm" has no effect, as there's no info to act upon
                err = confirm("Would you like to make this change? [y/n]: ")
                if err is not None:
                    return 0, ""

            upload_stats = upload_zip(
                backend,
                archive=tmp.name,
                verbose=args.verbose,
                output_type=args.output,
            )

            if args.output == display.OUTPUT_TYPE_JSON:
                output = get_upload_output_as_dict(
                    upload_stats,
                    test_results,
                    zip_info,
                    args.verbose,
                    args.skip_tests,
                    UPLOAD_RESULT_SUCCESS,
                    changes_summary,
                )
                print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))

        except BackendError as be_err:
            multi_err = BulkUploadMultipartError.from_jsons(convert_unicode(be_err))
            if args.output == display.OUTPUT_TYPE_TEXT:
                print_backend_issues(multi_err)
            elif args.output == display.OUTPUT_TYPE_JSON:
                output = get_failed_upload_as_dict(
                    multi_err,
                    test_results,
                    zip_info,
                    args.verbose,
                    args.skip_tests,
                    UPLOAD_RESULT_FAILURE,
                )
                print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
            return 1, ""

    return 0, ""


def dry_run_upload(backend: BackendClient, data: bytes, verbose, output_type) -> ChangesSummary:
    if verbose and output_type == display.OUTPUT_TYPE_TEXT:
        print(cli_output.header("Calculating changes..."))
    elif output_type == display.OUTPUT_TYPE_TEXT:
        print("Calculating changes...")
        print()  # new line

    params = AsyncBulkUploadParams(zip_bytes=data, dry_run=True)
    start_upload_response = backend.async_bulk_upload(params)
    while True:
        time.sleep(2)
        status_response = backend.async_bulk_upload_status(
            AsyncBulkUploadStatusParams(receipt_id=start_upload_response.data.receipt_id),
        )
        if status_response:
            break
    upload_stats = status_response.data
    changes_summary = ChangesSummary(
        message=f"Will add {upload_stats.rules.new} new rules and delete {upload_stats.rules.deleted} rules (total {upload_stats.rules.total} rules)",
        new=upload_stats.rules.new,
        delete=upload_stats.rules.deleted,
        modify=upload_stats.rules.modified,
        total=upload_stats.rules.total,
        new_ids=upload_stats.rules.new_ids,
        delete_ids=upload_stats.rules.deleted_ids,
        modify_ids=upload_stats.rules.modified_ids,
        total_ids=upload_stats.rules.total_ids,
    )
    return changes_summary


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
    backend: BackendClient,
    archive: str,
    verbose: bool,
    output_type: str,
) -> AsyncBulkUploadStatusResponse:
    with open(archive, "rb") as analysis_zip:
        if verbose and output_type == display.OUTPUT_TYPE_TEXT:
            print(cli_output.header("Uploading to Panther"))
        elif output_type == display.OUTPUT_TYPE_TEXT:
            print("Uploading to Panther")
            print()  # new line

        upload_params = AsyncBulkUploadParams(zip_bytes=analysis_zip.read(), dry_run=False)
        retry_count = 0

    # We should retry failures for up to 10 times
    max_retries = 10
    while True:
        try:
            start_upload_response = backend.async_bulk_upload(upload_params)
            if verbose and output_type == display.OUTPUT_TYPE_TEXT:
                print(INDENT, "- Upload started")

            while True:
                time.sleep(2)

                status_response = backend.async_bulk_upload_status(
                    AsyncBulkUploadStatusParams(receipt_id=start_upload_response.data.receipt_id),
                )
                if status_response is not None:
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


def confirm(warning_text: str) -> Optional[str]:
    warning_text = cli_output.warning(warning_text)
    choice = input(warning_text).lower()
    if choice != "y":
        print(cli_output.warning(f'Exiting upload due to entered response "{choice}"'))
        return "User did not confirm"

    print()  # new line
    return None


def get_upload_output_as_dict(
    upload_stats: AsyncBulkUploadStatusResponse | None,
    test_results: testing.TestResults,
    zip_infos: list[zipfile.ZipInfo],
    verbose: bool,
    skip_tests: bool,
    upload_result: str,
    changes_summary: ChangesSummary | None,
) -> dict:
    output: dict[str, Any] = {"result": upload_result}
    if upload_stats is not None:
        output["upload_statistics"] = asdict(upload_stats)
    if not skip_tests:
        output["tests"] = testing.test_output_dict(test_results, verbose)
    if verbose:
        output["registered_rules"] = [rule.id for rule in registered_rules()]
        if len(zip_infos) > 0:
            output["included_files"] = [info.filename for info in zip_infos]
    if changes_summary:
        output["summary"] = {
            "message": changes_summary["message"],
            "new": changes_summary["new"],
            "delete": changes_summary["delete"],
            "modify": changes_summary["modify"],
        }

    return output


def get_failed_upload_as_dict(
    err: BulkUploadMultipartError,
    test_results: testing.TestResults,
    zip_infos: list[zipfile.ZipInfo],
    verbose: bool,
    skip_tests: bool,
    upload_result: str,
) -> dict:
    output = {"failed_upload_details": err.asdict(), "result": upload_result}
    if not skip_tests:
        output["tests"] = testing.test_output_dict(test_results, verbose)
    if verbose:
        output["registered_rules"] = [rule.id for rule in registered_rules()]
        if len(zip_infos) > 0:
            output["included_files"] = [info.filename for info in zip_infos]

    return output


def print_registered_rules() -> None:
    if len(registered_rules()) == 0:
        return

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
    print(INDENT, cli_output.bold("Rules:"))
    print(INDENT * 2, "{:<9} {}".format("New:      ", status_response.data.rules.new))
    print(INDENT * 2, "{:<9} {}".format("Modified: ", status_response.data.rules.modified))
    print(INDENT * 2, "{:<9} {}".format("Deleted:  ", status_response.data.rules.deleted))
    print(INDENT * 2, "{:<9} {}".format("Total:    ", status_response.data.rules.total))
    print()  # new line


def print_backend_issues(err: BulkUploadMultipartError) -> None:
    print(cli_output.failed("Upload Failed"))
    if err.get_error() != "":
        print(INDENT, f"- {cli_output.failed(err.get_error())}")
    if len(err.get_issues()) > 0:
        for issue in err.get_issues():
            print(INDENT, f"- Error: {cli_output.failed(issue.error_message)}")
            print(INDENT, f"  Path:  {cli_output.failed(issue.path)}")


def print_changes_summary(changes_summary: ChangesSummary) -> None:
    print(changes_summary["message"])
    print()  # new line
    if changes_summary["new_ids"]:
        print(f"New [{changes_summary['new']}]:")
        for id_ in changes_summary["new_ids"]:
            print(f"+ {id_}")
        print()  # new line
    if changes_summary["delete_ids"]:
        print(f"Delete [{changes_summary['delete']}]:")
        for id_ in changes_summary["delete_ids"]:
            print(f"- {id_}")
        print()  # new line
    if changes_summary["modify_ids"]:
        print(f"Modify [{changes_summary['modify']}]:")
        for id_ in changes_summary["modify_ids"]:
            print(f"~ {id_}")
        print()  # new line
    print(cli_output.header("Changes Summary"))
    print(INDENT, f"New:     {changes_summary['new']:>3}")
    print(INDENT, f"Delete:  {changes_summary['delete']:>3}")
    print(INDENT, f"Modify:  {changes_summary['modify']:>3}")
    print()  # new line
