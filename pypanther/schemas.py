import logging
import os
from dataclasses import dataclass
from fnmatch import fnmatch
from itertools import filterfalse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

from ruamel.yaml import YAML
from ruamel.yaml.composer import ComposerError
from ruamel.yaml.parser import ParserError
from ruamel.yaml.scanner import ScannerError

from pypanther import cli_output
from pypanther.backend.client import BackendError, BackendResponse, ListSchemasParams, Schema, UpdateSchemaParams
from pypanther.backend.client import Client as BackendClient


@dataclass
class SchemaModification:
    # The path of the schema definition file
    filename: str
    # The schema name / identifier, e.g. Custom.SampleSchema
    name: Optional[str]
    # The Backend Client invocation response payload (PutUserSchema endpoint)
    backend_response: Optional[BackendResponse] = None
    # The schema specification in YAML form
    definition: Optional[dict[str, Any]] = None
    # Any error encountered during processing will be stored here
    error: Optional[str] = None
    # Flag to signify whether the schema did exist before
    existed: Optional[bool] = None
    # Flag to signify whether the schema was modified
    modified: Optional[bool] = None
    # Schema Object to be uploaded
    schema: Optional[Schema] = None


@dataclass
class ProcessedFile:
    # The deserialized schema
    yaml: Optional[dict[str, Any]] = None
    # The raw file contents
    raw: str = ""
    # Any error message produced during YAML parsing
    error: Optional[str] = None


class Manager:
    _SCHEMA_NAME_PREFIX = "Custom."
    _SCHEMA_FILE_GLOB_PATTERNS = ("*.yml", "*.yaml")

    def __init__(self, schemas_path: str, verbose: bool, dry_run: bool, backend_client: Optional[BackendClient] = None):
        absolute_path = normalize_path(schemas_path)
        if not absolute_path:
            if verbose:
                print(cli_output.warning("Schemas directory not found. Skipping schemas upload."))
            return

        self._path = absolute_path
        self._backend: Optional[BackendClient] = backend_client
        self._dry_run = dry_run
        self._files: Optional[List[str]] = None
        self._existing_upstream_schemas: Optional[List[Schema]] = None

        self._schemas_to_write = self.prepare()

        # we need to print errors from local files from this early on
        report_summary(absolute_path, self._schemas_to_write, verbose)

    def prepare(self) -> List[SchemaModification]:
        """
        Processes all potential schema files found in the given path.
        """
        if not self.files:
            logging.debug("No files found in path '%s'", self._path)
            return []

        processed_files = self.load_from_yaml(self.files)
        results = []
        for filename, processed_file in processed_files.items():
            # Add results for files that could not be loaded first
            # Skip any files with load errors, we have already included them in the previous loop
            if processed_file.error is not None:
                results.append(
                    SchemaModification(
                        name=None,
                        filename=filename,
                        error=processed_file.error,
                    ),
                )
                continue

            processed_yaml = cast(dict[str, Any], processed_file.yaml)  # type assertion. No-op in runtime
            logging.debug("Processing file %s", filename)

            name, error = self.extract_schema_name(processed_yaml, self._SCHEMA_NAME_PREFIX)
            mod = SchemaModification(filename=filename, name=name, error=error)

            if not mod.error:
                mod.schema = self.generate_schema_object(name, processed_file)
            results.append(mod)
        return results

    def check_upstream(self):
        """
        Check the schemas with the backend. This is in order to report changes during dry-runs and whatnot
        """
        for schema_mod in self._schemas_to_write:
            schema = schema_mod.schema

            existing_schema = self.find_schema(schema.name)
            if existing_schema is None:
                schema_mod.existed = False
                schema_mod.modified = False
                continue

            schema_mod.existed = True
            schema_mod.modified = schema_has_changed(existing_schema, schema)

            schema.revision = existing_schema.revision
            # even if the schema has not been changed, we will still do the operation to actually make sure we are
            # synced with the backend. If there has been a change we will get an error due to the revision conflict.
            schema.reference_url = existing_schema.reference_url if schema.reference_url == "" else schema.reference_url
            schema.description = existing_schema.description if schema.description == "" else schema.description

    def apply(self, verbose: bool) -> bool:
        """
        Processes all potential schema changes
        For update-ops it is required to retrieve description, revision number,
        and reference URL from the backend for each schema. More specifically:
        - A matching revision number must be provided when making update requests,
          otherwise validation fails.
        """
        errored = False

        for s in self.schemas:
            if s.error:
                continue
            if s.schema is None:
                raise ValueError("schema is None")
            try:
                s.backend_response = self.do_request(s.schema)
            except BackendError as exc:
                errored = True
                s.error = f"failure to update schema {s.name}: " f"message={exc}"

        report_summary(self._path, self.schemas, verbose)
        return errored

    def do_request(self, s: Schema) -> BackendResponse:
        """
        Update or create a schema based on the processed file contents.

        Note: Even if the schema has not been changed, we will still do the operation to actually make sure we are
        synced with the backend. If there has been a change we will get an error due to the revision conflict.
        """
        if self._backend is None:
            raise ValueError("backend is None")
        logging.debug("updating schema '%s' at revision '%d', using ", s.name, s.revision)

        return self._backend.update_schema(
            params=UpdateSchemaParams(
                name=s.name,
                spec=s.spec,
                revision=s.revision,
                reference_url=s.reference_url,
                description=s.description,
                field_discovery_enabled=s.field_discovery_enabled,
            ),
        )

    @staticmethod
    def generate_schema_object(name: str, processed_file: ProcessedFile) -> Schema:
        if not processed_file.yaml:
            raise ValueError("processed_file.yaml is None")

        return Schema(
            name=name,
            spec=processed_file.raw,
            reference_url=processed_file.yaml.get("referenceURL", ""),
            description=processed_file.yaml.get("description", ""),
            field_discovery_enabled=processed_file.yaml.get("fieldDiscoveryEnabled", True),
            # This will be filled in with the correct value later in case it exists
            revision=0,
            # We don't care about the following at this point. We won't use them during the update
            created_at="",
            updated_at="",
            is_managed=False,
        )

    @property
    def schemas(self) -> List[SchemaModification]:
        if hasattr(self, "_schemas_to_write"):
            return self._schemas_to_write
        return []

    @property
    def files(self) -> List[str]:
        """
        Resolves the list of schema definition files.

        Returns
        -------
            A list of absolute paths to the schema files.

        """
        if self._files is None:
            matching_filenames = discover_files(self._path, self._SCHEMA_FILE_GLOB_PATTERNS)
            self._files = ignore_schema_test_files(matching_filenames)
        return self._files

    @property
    def existing_upstream_schemas(self) -> List[Schema]:
        """
        Retrieves and caches in the instance state the list
        of available user-defined schemas.

        Returns
        -------
             List of user-defined schema records.

        """
        if self._backend is None:
            raise ValueError("backend is None")

        if self._existing_upstream_schemas is None:
            resp = self._backend.list_schemas(ListSchemasParams(is_managed=False))
            if not resp.status_code == 200:
                raise RuntimeError("unable to retrieve custom schemas")
            self._existing_upstream_schemas = resp.data.schemas
        return self._existing_upstream_schemas

    def find_schema(self, name: str) -> Optional[Schema]:
        """
        Find schema by name.

        Returns
        -------
             The decoded YAML schema or None if no matching name is found.

        """
        for schema in self.existing_upstream_schemas:
            if schema.name == name:
                return schema
        return None

    @staticmethod
    def load_from_yaml(files: List[str]) -> Dict[str, ProcessedFile]:
        processed_files = {}
        yaml_parser = YAML(typ="safe")

        for filename in files:
            logging.debug("Loading schema from file %s", filename)
            processed_file = ProcessedFile()
            try:
                with open(filename, encoding="utf-8") as schema_file:
                    raw = schema_file.read()
                processed_file.raw = raw
                processed_file.yaml = yaml_parser.load(raw)
            except (ParserError, ScannerError, ComposerError) as exc:
                processed_file.error = f"invalid YAML: {exc}"
            processed_files[filename] = processed_file
        return processed_files

    @staticmethod
    def extract_schema_name(definition: dict[str, Any], prefix: str) -> Tuple[str, Optional[str]]:
        name = definition.get("schema")

        if name is None:
            return "", "key 'schema' not found"

        if not name.startswith(prefix):
            return (
                "",
                f"'schema' field: value must start" f" with the prefix '{prefix}'",
            )

        if len(name) > 255:
            return "", "'schema' field: value should not exceed 255 characters"

        return name, None


def discover_files(base_path: str, patterns: Tuple[str, ...]) -> List[str]:
    """
    Recursively locates files that match the given glob patterns.

    Args:
    ----
         base_path: the base directory for recursively searching for files
         patterns: a list of glob patterns that the filenames should match

    Returns:
    -------
        A sorted list of absolute paths.

    """
    files = []
    for directory, _, filenames in os.walk(base_path):
        for filename in filenames:
            for pattern in patterns:
                if fnmatch(filename, pattern):
                    files.append(os.path.join(directory, filename))
    return sorted(files)


def ignore_schema_test_files(paths: List[str]) -> List[str]:
    """
    Detect and ignore files that contain schema tests.
    """
    return list(filterfalse(_contains_schema_tests, paths))


def _contains_schema_tests(filename: str) -> bool:
    """
    Check if a file contains YAML document(s) that describe test cases for custom schemas.
    Note that a test case file may contain multiple YAML documents.

    We require that files containing test cases have a specific suffix and extension.
    """
    if not filename.endswith("_tests.yml"):
        return False

    yaml_parser = YAML(typ="safe")

    with open(filename, encoding="utf-8") as stream:
        try:
            yaml_documents: List[Dict[str, Any]] = yaml_parser.load_all(stream)
        except (ParserError, ScannerError, ComposerError):
            return False

        documents = list(yaml_documents)

    if not documents:
        return False

    fields = {x.lower() for x in documents[0].keys()}

    # - "input" and "logtype" are expected to be always present
    # - at least one of "result", "results" fields is required
    return {"input", "logtype", "result"}.issubset(fields) or {
        "input",
        "logtype",
        "results",
    }.issubset(fields)


def normalize_path(path: str) -> Optional[str]:
    """
    Resolve the given path to its absolute form, taking into
    account user home prefix notation.
    """
    absolute_path = Path.resolve(Path.expanduser(Path(path)))
    if not os.path.exists(absolute_path):
        return None
    return str(absolute_path)


def report_summary(base_path: str, results: List[SchemaModification], verbose: bool):
    """
    Translate uploader results to descriptive status messages and prints them.
    Prints only on verbose and on errors.
    """
    for result in sorted(results, key=lambda r: r.filename):
        filename = result.filename.split(base_path)[-1].strip(os.path.sep)
        if result.error:
            print(
                cli_output.failed(
                    f"Failed to update schema from definition" f" in file '{filename}':" f"{result.error}",
                ),
            )
        elif verbose:
            if result.modified:
                print(f"Successfully updated schema '{result.name}' from definition in file '{filename}'")
            else:
                print(f"Successfully created schema '{result.name}' from definition in file '{filename}'")


def schema_has_changed(existing_schema: Schema, new_schema: Schema) -> bool:
    """
    Compare the schema definition in the processed file with the existing schema.
    """
    yaml_parser = YAML(typ="safe")

    return yaml_parser.load(existing_schema.spec) != yaml_parser.load(new_schema.spec)
