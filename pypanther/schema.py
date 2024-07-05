import abc
from typing import List, Optional

from .field import PantherField, PantherFieldString, PantherFieldTimestamp, PantherTimestampFormat


class PantherParser(abc.ABCMeta):
    # TODO: Implement this class
    pass


class PantherParserCSV(PantherParser):
    # TODO: Implement this class
    HasHeader: bool = True
    Delimiter: str = ","


class PantherSchema(abc.ABCMeta):
    Parser: Optional[PantherParser]
    Description: str
    Fields: List[PantherField]
    Archived: bool = False


class OnePassword_ItemUsage(PantherSchema):
    Description = "OnePassword Item Usage"
    Fields = [
        PantherFieldString(
            name="UUID",
            description="The ID of the item",
            required=True),
        PantherFieldTimestamp(
            name="timestamp",
            description="The timestamp of the event",
            time_formats=[PantherTimestampFormat.RFC3339]),
        PantherFieldString(
            name="action",
            description="The action performed on the item"),
    ]
