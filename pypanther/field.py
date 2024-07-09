import abc
import dataclasses
import datetime
from enum import Enum
from typing import List, Optional, final, Any


class Indicator(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class FieldType(Enum):
    STRING = "string"
    INT = "int"
    SMALLINT = "smallint"
    BIGINT = "bigint"
    FLOAT = "float"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    ARRAY = "array"
    OBJECT = "object"
    JSON = "json"


class TimestampFormat(Enum):
    RFC3339 = "rfc3339"
    UNIX_AUTO = "unix_auto"
    UNIX = "unix"
    UNIX_MS = "unix_ms"
    UNIX_NS = "unix_ns"
    UNIX_US = "unix_us"


@dataclasses.dataclass
class Field(metaclass=abc.ABCMeta):
    description: Optional[str] = None
    required: bool = False
    # THe name of the field.
    # If not specified, we use the name of the field in the dataclass
    name: Optional[str] = None


@final
@dataclasses.dataclass
class String(Field, str):
    indicators: List[Indicator] = list


def new_string(indicators: List[Indicator] = list,
               description: Optional[str] = None) -> str:
    return String(indicators=indicators, description=description)


@final
@dataclasses.dataclass
class SmallInt(Field, int):
    """ Represents a 32-bit signed integer """


def new_smallint(description: Optional[str] = None) -> int:
    return SmallInt(description=description)


@final
@dataclasses.dataclass
class BigInt(Field, int):
    """ Represents a 64-bit signed integer """


def new_bigint(description: Optional[str] = None) -> int:
    return BigInt(description=description)


@final
@dataclasses.dataclass
class Float(Field, float):
    """ Represents a floating point number """


def new_float(description: Optional[str] = None) -> float:
    return Float(description=description)


@final
@dataclasses.dataclass
class Bool(Field, bool):
    """ Represents a boolean value """


def new_bool(description: Optional[str] = None) -> Bool:
    return Bool(description=description)


@final
@dataclasses.dataclass
class Timestamp(Field, datetime.datetime):
    """ Represents a timestamp """
    time_formats: List[str | TimestampFormat] = None
    is_event_time: bool = False


def new_timestamp(time_formats: List[str | TimestampFormat],
                  is_event_time: bool = False,
                  description: Optional[str] = None) -> datetime.datetime:
    return Timestamp(description=description, time_formats=time_formats, is_event_time=is_event_time)


@final
@dataclasses.dataclass
class Array(Field, list):
    """ Represents an array of items """
    item: Field = None


def new_array(item: Field, description: Optional[str] = None) -> list:
    return Array(description=description, item=item)


@final
@dataclasses.dataclass
class Object(Field, dict[str, Any]):
    """ Represents an object"""
    fields: List[Field] = None


def new_object(fields: List[Field], description: Optional[str] = None) -> dict[str, Any]:
    return Object(description=description, fields=fields)


@final
@dataclasses.dataclass
class JSON(Field, Any):
    """ Represents a JSON object """


def new_json(description: Optional[str] = None) -> Any:
    return JSON(description=description)
