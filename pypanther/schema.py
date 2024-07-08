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



class Schema(abc.ABCMeta):
    Parser: Optional[PantherParser]
    Description: str
    Archived: bool = False


@dataclasses.dataclass
class CustomSchemaOne(Schema):
    id: str
    name: str


@dataclasses.dataclass
class MyClassTwo(Schema):
    id: str
    name: str
    description: str


class OnePassword_ItemUsage(Schema):
    UUID = String(
        Description="The ID of the item",
        Required=True)
    timestamp = Timestamp(
        Description="The timestamp of the event",
        TimeFormats=[TimestampFormat.RFC3339])
    action = String(
        Description="The action performed on the item")
