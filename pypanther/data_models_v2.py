from abc import ABC
import copy
from dataclasses import dataclass
import datetime
from enum import Enum
from typing import List, Optional, final

from pydantic import BaseModel

from pypanther import LogType
from pypanther.utils import try_asdict

"""This file contains data model definitions for the PyPanther package.
It is still in development and is subject to change.
"""


class FieldType(str, Enum):
    """Enumeration of all possible field types."""

    STRING = "string"
    INT = "int"
    SMALL_INT = "smallint"
    BIG_INT = "bigint"
    FLOAT = "float"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    ARRAY = "array"
    OBJECT = "object"
    JSON = "json"


_FIELD_MAPPING_ALL_ATTRIBUTES = [
    "log_type",
    "field_path",
]


@dataclass
class FieldMapping:
    """Represents a field mapping in a data model."""

    # TODO: Right now we support field_paths but we should be able to support transformations as well
    # TODO: This could be pointing to a schema attribute in the log type

    log_type: LogType | str
    """The log type that this field belongs to."""

    field_path: str
    """The path to the field in the log."""

    def asdict(self):
        """Returns a dictionary representation of the instance."""
        return {key: try_asdict(getattr(self, key)) for key in _FIELD_MAPPING_ALL_ATTRIBUTES if hasattr(self, key)}


_FIELD_ALL_ATTRIBUTES = [
    "type",
    "mappings",
]


@dataclass
class Field(ABC):
    """Represents a field in a data model."""
    type: FieldType
    """The type of the field."""

    mappings: list[FieldMapping]
    """Mappings describe how the data model field is derived from the various log types."""


@final
@dataclass
class String(str, Field):
    """ Represents a string """
    pass


def new_string(mappings: list[FieldMapping]) -> String:
    return String(type=FieldType.STRING, mappings=mappings)


@final
@dataclass
class SmallInt(Field, int):
    """ Represents a 32-bit signed integer """
    pass


def new_smallint(mappings: list[FieldMapping]) -> SmallInt:
    return SmallInt(type=FieldType.SMALL_INT, mappings=mappings)


@final
@dataclass
class BigInt(int, Field):
    """ Represents a 64-bit signed integer """
    pass


def new_bigint(mappings: list[FieldMapping]) -> BigInt:
    return BigInt(type=FieldType.BIG_INT, mappings=mappings)


@final
@dataclass
class Float(float, Field):
    """ Represents a floating point number """
    pass


def new_float(mappings: list[FieldMapping]) -> Float:
    return Float(type=FieldType.FLOAT, mappings=mappings)


@final
@dataclass
class Bool(bool, Field):
    """ Represents a boolean value """
    pass


def new_bool(mappings: list[FieldMapping]) -> Bool:
    return Bool(type=FieldType.BOOLEAN, mappings=mappings)


@final
@dataclass
class Timestamp(datetime.datetime, Field):
    """ Represents a timestamp """
    pass


def new_timestamp(mappings: list[FieldMapping]) -> datetime.datetime:
    return Timestamp(type=FieldType.TIMESTAMP, mappings=mappings)


@final
@dataclass
class Array(list, Field):
    """ Represents an array of items """
    pass


def new_array(mappings: list[FieldMapping]) -> list:
    return Array(type=FieldType.ARRAY, mappings=mappings)


@final
@dataclass
class Object(dict[str, any], Field):
    """ Represents an object"""
    pass


def new_object(mappings: list[FieldMapping]) -> dict[str, any]:
    return Object(type=FieldType.OBJECT, mappings=mappings)


@final
@dataclass
class JSON(any, Field):
    """ Represents a JSON object """
    pass


def new_json(mappings: list[FieldMapping]) -> any:
    return JSON(type=FieldType.JSON, mappings=mappings)


class DataModel(BaseModel):
    """A Panther data model. This class should be subclassed to create a new Data Model."""
