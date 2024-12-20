import argparse
import base64
import importlib
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

import requests

from pypanther import cli_output, display, schemas, testing
from pypanther.backend.client import (
    BackendError,
    BulkUploadDetectionsError,
    BulkUploadDetectionsParams,
    BulkUploadDetectionsResults,
    BulkUploadDetectionsStatusParams,
    BulkUploadPresignedURLParams,
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

# There is no hard limit on the BE size, but setting this to 10MB for now to avoid customers uploading by mistake large files
UPLOAD_SIZE_LIMIT_MB = 10
UPLOAD_SIZE_LIMIT_BYTES = UPLOAD_SIZE_LIMIT_MB * 1024 * 1024


class ChangesSummary(TypedDict):
    # rules
    new_rule_ids: list[str]
    delete_rule_ids: list[str]
    modify_rule_ids: list[str]
    total_rule_ids: list[str]
    # schemas
    new_schema_names: list[str]
    modified_schema_names: list[str]
    existed_schema_names: list[str]


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

    test_results = testing.TestResults()
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
            session_id = upload_zip(backend=backend, archive=tmp.name, verbose=args.verbose, output_type=args.output)
        except BackendError as be_err:
            multi_err = BulkUploadDetectionsError.from_json(convert_unicode(be_err))
            if args.output == display.OUTPUT_TYPE_TEXT:
                print_upload_detection_error(multi_err)
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

    changes_summary = ChangesSummary(
        new_rule_ids=[],
        delete_rule_ids=[],
        modify_rule_ids=[],
        total_rule_ids=[],
        new_schema_names=[],
        modified_schema_names=[],
        existed_schema_names=[],
    )

    # Prepare schemas first
    manager = schemas.Manager(args.schemas_path, verbose=args.verbose, dry_run=args.dry_run, backend_client=backend)
    manager.check_upstream()
    for schema_to_be_written in manager.schemas:
        if schema_to_be_written.error:  # stop if there's a single error. It's already been printed
            return 1, ""
        if not schema_to_be_written.name:
            raise ValueError("Schema name is required")
        if schema_to_be_written.modified:
            changes_summary["modified_schema_names"].append(schema_to_be_written.name)
        elif schema_to_be_written.existed:
            changes_summary["existed_schema_names"].append(schema_to_be_written.name)
        else:
            changes_summary["new_schema_names"].append(schema_to_be_written.name)

    try:
        if not args.confirm:
            if not args.skip_summary or args.dry_run:
                rules_changes_summary = dry_run_rule_upload(
                    backend=backend,
                    session_id=session_id,
                    verbose=args.verbose,
                    output_type=args.output,
                )
                changes_summary["new_rule_ids"] = rules_changes_summary["new_rule_ids"]
                changes_summary["delete_rule_ids"] = rules_changes_summary["delete_rule_ids"]
                changes_summary["modify_rule_ids"] = rules_changes_summary["modify_rule_ids"]
                changes_summary["total_rule_ids"] = rules_changes_summary["total_rule_ids"]

                if args.output == display.OUTPUT_TYPE_JSON:
                    output = get_upload_output_as_dict(
                        None,
                        test_results,
                        [],
                        args.verbose,
                        args.skip_tests,
                        UPLOAD_RESULT_SUCCESS,
                        changes_summary,
                    )
                    print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
                else:
                    print_changes_summary(changes_summary)

            if args.dry_run:
                return 0, ""

            if not args.skip_summary:
                # if the user skips calculating the summary of the changes,
                # "--confirm" has no effect, as there's no info to act upon
                err = confirm("Would you like to make this change? [y/n]: ")
                if err is not None:
                    return 0, ""

        # actually upload schemas
        upload_errored = manager.apply(args.verbose)
        if upload_errored:
            return 1, ""

        rule_upload_stats = run_rule_upload(
            backend=backend,
            session_id=session_id,
            verbose=args.verbose,
            output_type=args.output,
        )
    except BackendError as err:
        multi_err = BulkUploadDetectionsError.from_json(convert_unicode(err))
        if args.output == display.OUTPUT_TYPE_TEXT:
            print_upload_detection_error(multi_err)
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

    if args.output == display.OUTPUT_TYPE_JSON:
        output = get_upload_output_as_dict(
            rule_upload_stats,
            test_results,
            zip_info,
            args.verbose,
            args.skip_tests,
            UPLOAD_RESULT_SUCCESS,
            changes_summary,
        )
        print(json.dumps(output, indent=display.JSON_INDENT_LEVEL))
    else:
        print_upload_statistics(rule_upload_stats, changes_summary)

    return 0, ""


def dry_run_rule_upload(backend: BackendClient, session_id: str, verbose: bool, output_type: str) -> ChangesSummary:
    if verbose and output_type == display.OUTPUT_TYPE_TEXT:
        print(cli_output.header("Calculating changes..."))
    elif output_type == display.OUTPUT_TYPE_TEXT:
        print("Calculating changes...")
        print()  # new line

    start_upload_response = backend.bulk_upload_detections(
        BulkUploadDetectionsParams(session_id=session_id, dry_run=True),
    )
    while True:
        time.sleep(1)
        status_response = backend.bulk_upload_detections_status(
            BulkUploadDetectionsStatusParams(job_id=start_upload_response.data.job_id),
        )
        if verbose and output_type == display.OUTPUT_TYPE_TEXT:
            print(f"Got status response {status_response.data.status}")
        if status_response.data.status == "Failed":
            raise BackendError(status_response.data.message)
        if status_response.data.status == "Succeeded":
            upload_stats = status_response.data.results
            if not upload_stats:
                raise BackendError("No results found in status response")
            changes_summary = ChangesSummary(
                new_rule_ids=upload_stats.new_rule_ids,
                delete_rule_ids=upload_stats.deleted_rule_ids,
                modify_rule_ids=upload_stats.modified_rule_ids,
                total_rule_ids=upload_stats.total_rule_ids,
                new_schema_names=[],
                modified_schema_names=[],
                existed_schema_names=[],
            )
            return changes_summary


def run_rule_upload(
    backend: BackendClient,
    session_id: str,
    verbose: bool,
    output_type: str,
) -> BulkUploadDetectionsResults:
    resp = backend.bulk_upload_detections(
        BulkUploadDetectionsParams(session_id=session_id, dry_run=False),
    )

    while True:
        time.sleep(1)
        status_response = backend.bulk_upload_detections_status(
            BulkUploadDetectionsStatusParams(job_id=resp.data.job_id),
        )
        if verbose and output_type == display.OUTPUT_TYPE_TEXT:
            print(f"Got status response {status_response.data.status}")
        if status_response.data.status == "Failed":
            raise BackendError(status_response.data.message)
        if status_response.data.status == "Succeeded":
            results = status_response.data.results
            if not results:
                raise BackendError("No results found in status response")
            return results


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


# Uploads the zip file and returns the session_id
def upload_zip(
    backend: BackendClient,
    archive: str,
    verbose: bool,
    output_type: str,
) -> str:
    if verbose and output_type == display.OUTPUT_TYPE_TEXT:
        print("requesting presigned URL for upload")
        print()

    pypanther_version = importlib.metadata.version("pypanther")
    response = backend.bulk_upload_presigned_url(
        params=BulkUploadPresignedURLParams(pypanther_version=pypanther_version),
    )

    with open(archive, "rb") as analysis_zip:
        if output_type == display.OUTPUT_TYPE_TEXT:
            if verbose:
                print(
                    f"Uploading detections zip file to URL: {response.data.detections_url} with pypanther version {pypanther_version}",
                )
            else:
                print("Uploading detections...")

        headers = {"x-amz-meta-pypantherversion": pypanther_version}
        data = base64.b64encode(analysis_zip.read()).decode("utf-8")
        # The timeout is set to 300 seconds to allow for larger files to be uploaded
        requests.put(response.data.detections_url, data=data, headers=headers, timeout=300)
        if verbose and output_type == display.OUTPUT_TYPE_TEXT:
            print("finished uploading detections zip file")

        return response.data.session_id


def confirm(warning_text: str) -> Optional[str]:
    warning_text = cli_output.warning(warning_text)
    choice = input(warning_text).lower()
    if choice != "y":
        print(cli_output.warning(f'Exiting upload due to entered response "{choice}"'))
        return "User did not confirm"

    print()  # new line
    return None


def get_upload_output_as_dict(
    upload_stats: BulkUploadDetectionsResults | None,
    test_results: testing.TestResults,
    zip_infos: list[zipfile.ZipInfo],
    verbose: bool,
    skip_tests: bool,
    upload_result: str,
    changes_summary: ChangesSummary | None,
) -> dict:
    output: dict[str, Any] = {"result": upload_result}
    if upload_stats:
        schema_stats = {}
        if changes_summary:
            schema_stats = {
                "new_schema_names": changes_summary["new_schema_names"],
                "modified_schema_names": changes_summary["modified_schema_names"],
                "existed_schema_names": changes_summary["existed_schema_names"],
            }
        output["upload_statistics"] = {
            "rules": asdict(upload_stats),
            "schemas": schema_stats,
        }
    if not skip_tests:
        output["tests"] = testing.test_output_dict(test_results, verbose)
    if verbose:
        output["registered_rules"] = [rule.id for rule in registered_rules()]
        if len(zip_infos) > 0:
            output["included_files"] = [info.filename for info in zip_infos]
    if changes_summary:
        output["summary"] = {
            "new_rule_ids": len(changes_summary["new_rule_ids"]),
            "delete_rule_ids": len(changes_summary["delete_rule_ids"]),
            "modify_rule_ids": len(changes_summary["modify_rule_ids"]),
            "new_schema_names": len(changes_summary["new_schema_names"]),
            "modified_schema_names": len(changes_summary["modified_schema_names"]),
            "existed_schema_names": len(changes_summary["existed_schema_names"]),
        }

    return output


def get_failed_upload_as_dict(
    err: BulkUploadDetectionsError,
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


def print_upload_statistics(rule_results: BulkUploadDetectionsResults, schema_results: ChangesSummary) -> None:
    print(cli_output.header("Upload Statistics"))
    print(INDENT, cli_output.bold("Rules:"))
    print(INDENT * 2, "{:<9} {:>4}".format("New:      ", len(rule_results.new_rule_ids)))
    print(INDENT * 2, "{:<9} {:>4}".format("Modified: ", len(rule_results.modified_rule_ids)))
    print(INDENT * 2, "{:<9} {:>4}".format("Deleted:  ", len(rule_results.deleted_rule_ids)))
    print(INDENT * 2, "{:<9} {:>4}".format("Total:    ", len(rule_results.total_rule_ids)))
    print()  # new line
    print(INDENT, cli_output.bold("Schemas:"))
    print(INDENT * 2, "{:<9} {:>4}".format("New:          ", len(schema_results["new_schema_names"])))
    print(INDENT * 2, "{:<9} {:>4}".format("Modified:     ", len(schema_results["modified_schema_names"])))
    print(INDENT * 2, "{:<9} {:>4}".format("Not Modified: ", len(schema_results["existed_schema_names"])))
    print()  # new line


def print_upload_detection_error(err: BulkUploadDetectionsError) -> None:
    print(cli_output.failed("Upload Failed"))
    if err.error != "":
        print(INDENT, f"- {cli_output.failed(err.error)}")


def print_changes_summary(changes_summary: ChangesSummary) -> None:
    print("Changes Summary:")
    print()  # new line
    if changes_summary["new_rule_ids"]:
        print(f"New Rules [{len(changes_summary['new_rule_ids'])}]:")
        for id_ in changes_summary["new_rule_ids"]:
            print(f"+ {id_}")
        print()  # new line
    if changes_summary["delete_rule_ids"]:
        print(f"Delete Rules [{len(changes_summary['delete_rule_ids'])}]:")
        for id_ in changes_summary["delete_rule_ids"]:
            print(f"- {id_}")
        print()  # new line
    if changes_summary["modify_rule_ids"]:
        print(f"Modify Rules [{len(changes_summary['modify_rule_ids'])}]:")
        for id_ in changes_summary["modify_rule_ids"]:
            print(f"~ {id_}")
        print()  # new line
    if changes_summary["new_schema_names"]:
        print(f"New Schemas [{len(changes_summary['new_schema_names'])}]:")
        for name in changes_summary["new_schema_names"]:
            print(f"+ {name}")
        print()  # new line
    if changes_summary["modified_schema_names"]:
        print(f"Modify Schemas [{len(changes_summary['modified_schema_names'])}]:")
        for name in changes_summary["modified_schema_names"]:
            print(f"~ {name}")
    print(cli_output.header("Changes Summary"))
    print(INDENT, f"New Rules:      {len(changes_summary['new_rule_ids']):>4}")
    print(INDENT, f"Modified Rules: {len(changes_summary['modify_rule_ids']):>4}")
    print(INDENT, f"Deleted Rules:  {len(changes_summary['delete_rule_ids']):>4}")
    print(INDENT, f"Total Rules:    {len(changes_summary['total_rule_ids']):>4}")
    print()  # new line
    print(INDENT, f"New Schemas:          {len(changes_summary['new_schema_names']):>4}")
    print(INDENT, f"Modified Schemas:     {len(changes_summary['modified_schema_names']):>4}")
    print(INDENT, f"Not Modified Schemas: {len(changes_summary['existed_schema_names']):>4}")
    print()  # new line
