import os
from abc import ABC, abstractmethod


class Lookup:
    """
    A Lookup table base configuration.

    Attributes
    ----------
    _analysis_type : str
        The type of analysis, default is "LOOKUP_TABLE".
    lookup_type : str
        The type of lookup.
    enabled : bool
        Indicates if the lookup is enabled/active, default is True.
    lookup_id : str
        The unique identifier for the lookup which will be used in rules/queries.
    schema_id : str
        The schema identifier associated with the lookup data.
    log_type_map : dict
        A mapping of log types to use when the schema does not contain indicator fields.
    description : str
        A description of what the lookup does.
    reference : str
        A URL reference for the lookup.
    tags : list
        A list of tags associated with the lookup to help with organization.

    Methods
    -------
    to_dict() -> dict:
        Converts the Lookup instance to a dictionary representation.
    validate_log_type_map(log_type_map: dict) -> None:
        Validates the structure of the log_type_map dictionary.

    """

    _analysis_type: str = "LOOKUP_TABLE"
    lookup_type: str = ""
    enabled: bool = True
    lookup_id: str = ""
    schema_id: str = ""
    log_type_map: dict = {}  # Use the data model v2 FieldMapping class
    description: str = ""
    reference: str = ""
    tags: list = []

    def to_dict(self) -> dict:
        return {
            "analysis_type": self._analysis_type,
            "enabled": self.enabled,
            "lookup_name": self.lookup_id,
            "schema": self.schema_id,
            "log_type_map": self.log_type_map,
            "description": self.description,
            "reference": self.reference,
            "tags": self.tags,
        }

    @staticmethod
    def validate_log_type_map(log_type_map: dict) -> None:
        if not isinstance(log_type_map, dict):
            raise TypeError("LogTypeMap must be a dictionary.")
        if "PrimaryKey" not in log_type_map or "AssociatedLogTypes" not in log_type_map:
            raise ValueError("LogTypeMap must contain 'PrimaryKey' and 'AssociatedLogTypes' fields.")
        if not isinstance(log_type_map["AssociatedLogTypes"], list):
            raise TypeError("AssociatedLogTypes must be a list.")
        for item in log_type_map["AssociatedLogTypes"]:
            if not isinstance(item, dict):
                raise TypeError("Each item in AssociatedLogTypes must be a dictionary.")
            if "LogType" not in item or "Selectors" not in item:
                raise ValueError("Each item in AssociatedLogTypes must contain 'LogType' and 'Selectors' fields.")
            if not isinstance(item["Selectors"], list):
                raise TypeError("Selectors must be a list.")


class FileLookup(Lookup):
    lookup_type = "FILE"
    filename: str = ""

    def validate(self):
        if not self.filename:
            raise ValueError("Filename must be provided a file lookup.")
        if not isinstance(self.filename, str):
            raise TypeError("Filename must be a string.")
        if not os.path.isfile(self.filename):
            raise FileNotFoundError(f"The file {self.filename} does not exist.")
        if not (self.filename.endswith(".jsonl") or self.filename.endswith(".csv")):
            raise ValueError("Filename must end with .jsonl or .csv.")


class S3Lookup(Lookup):
    lookup_type = "S3"
    refresh: "S3Lookup.Refresh"

    class Refresh:
        """
        The data refresh configuration for AWS S3 lookups.

        Attributes
        ----------
        aws_role_arn : str
            The Amazon Resource Name (ARN) of the AWS role.
        s3_object_path : str
            The S3 object path.
        period_minutes : int
            The refresh period in minutes. Must be one of the following values: 15, 30, 60, 180, 720, 1440.

        Methods
        -------
        validate():
            Validates the attributes of the Refresh instance.
        to_dict() -> dict:
            Converts the Refresh instance to a dictionary.

        """

        def __init__(self, aws_role_arn: str, s3_object_path: str, period_minutes: int):
            self.aws_role_arn = aws_role_arn
            self.s3_object_path = s3_object_path
            self.period_minutes = period_minutes  # Use the new Period class
            self.validate()

        def validate(self):
            if not isinstance(self.aws_role_arn, str):
                raise TypeError("RoleARN must be a string.")
            if not isinstance(self.s3_object_path, str):
                raise TypeError("ObjectPath must be a string.")
            if self.period_minutes not in [15, 30, 60, 180, 720, 1440]:
                raise ValueError("PeriodMinutes must be one of the following values: 15, 30, 60, 180, 720, 1440.")

        def to_dict(self) -> dict:
            return {
                "role_arn": self.aws_role_arn,
                "object_path": self.s3_object_path,
                "period_minutes": self.period_minutes,
            }


class ScheduledQueryLookup(Lookup):
    """
    A lookup that runs a query on a schedule to populate the lookup data.

    Attributes
    ----------
        lookup_type (str): A constant string representing the type of lookup, which is "SCHEDULED_QUERY".
        schedule (str or None): The schedule for the query. Default is None.
        query (str or None): The query to be executed. Default is None.

    """

    lookup_type = "SCHEDULED_QUERY"
    schedule = None  # Use the upcoming Schedule class
    query = None  # Use the upcoming Query class


class APILookup(Lookup, ABC):
    """
    API lookups pull data from an API on a schedule and are built by the customer.
    This is a future-facing feature that will need:
        - Secrets management via `pypanther` CLI
        - API rate limiting
        - Error handling
        - Timeouts
    """

    lookup_type = "API"

    @abstractmethod
    def pull_lookup_data(self) -> list[dict]:
        pass


class InlineLookup(Lookup):
    """
    InlineLookup allows lookup data to be specified directly without pulling or loading from a file.

    Attributes
    ----------
        data (list[dict]): A list of dictionaries containing the data for the lookup.

    Methods
    -------
        validate():
            Validates the data attribute to ensure it is a list of dictionaries.
            Raises a ValueError if data is not provided.
            Raises a TypeError if data is not a list or if any item in data is not a dictionary.

    """

    lookup_type = "INLINE"
    data: list[dict]

    def validate(self):
        if not self.data:
            raise ValueError("Data must be provided for an inline lookup.")
        if not isinstance(self.data, list):
            raise TypeError("Data must be a list.")
        if not all(isinstance(item, dict) for item in self.data):
            raise TypeError("Each item in data must be a dictionary.")
