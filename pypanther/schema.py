import abc
import dataclasses
from typing import List, Optional

from .field import Field, String, Timestamp, TimestampFormat


class PantherParser(abc.ABCMeta):
    # TODO: Implement this class
    pass


class PantherParserCSV(PantherParser):
    # TODO: Implement this class
    HasHeader: bool = True
    Delimiter: str = ","


@dataclasses.dataclass
class PantherSchema(abc.ABCMeta):
    Parser: Optional[PantherParser]
    Description: str
    Archived: bool = False


class OnePassword_ItemUsage(PantherSchema):
    UUID = String(
        Description="The ID of the item",
        Required=True)
    timestamp = Timestamp(
        Description="The timestamp of the event",
        TimeFormats=[TimestampFormat.RFC3339])
    action = String(
        Description="The action performed on the item")

