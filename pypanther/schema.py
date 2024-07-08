import abc
from typing import Optional

from .field import String, Timestamp, TimestampFormat


class PantherParser(abc.ABCMeta):
    # TODO: Implement this class
    pass


class PantherParserCSV(PantherParser):
    # TODO: Implement this class
    has_header: bool = True
    delimiter: str = ","


class Schema(abc.ABCMeta):
    parser: Optional[PantherParser]
    description: str
    archived: bool = False


class CustomSchemaOne(Schema):
    id: str
    name: str


class MyClassTwo(Schema):
    id: str
    name: str
    description: str


class OnePasswordItemUsage(Schema):
    UUID = String(
        description="The ID of the item",
        required=True)
    timestamp = Timestamp(
        description="The timestamp of the event",
        time_formats=[TimestampFormat.RFC3339])
    action = String(
        description="The action performed on the item")
