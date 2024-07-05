import abc
import dataclasses
import time
from enum import Enum
from typing import List, Optional, final, Any


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


# - name: uuid
# required: true
# description: The UUID of the event.
# type: string


@dataclasses.dataclass
class Field(metaclass=abc.ABCMeta):
    Description: Optional[str] = None
    Required: bool = False


@final
@dataclasses.dataclass
class String(Field):
    Indicators: List[str] = list

@final
@dataclasses.dataclass
class Int(Field):


@final
@dataclasses.dataclass
class BigInt(Field):

@final
@dataclasses.dataclass
class Float(Field):


@final
@dataclasses.dataclass
class Bool(Field):


@final
@dataclasses.dataclass
class Timestamp(Field):
    TimeFormats: List[str | TimestampFormat] = list
    IsEventTime: bool = False


@final
@dataclasses.dataclass
class Array(Field):
    Item: Field = list

@final
@dataclasses.dataclass
class Object(Field):
    Fields: List[Field] = list


@final
@dataclasses.dataclass
class Json(Field):

