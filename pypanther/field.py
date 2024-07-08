import abc
import dataclasses
from enum import Enum
from typing import List, Optional, final, Any, Dict


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
class String(Field):
    Indicators: List[Indicator] = list


@final
@dataclasses.dataclass
class Int(Field):
    """ Represents a 32-bit signed integer """


@final
@dataclasses.dataclass
class BigInt(Field):
    """ Represents a 64-bit signed integer """


@final
@dataclasses.dataclass
class Float(Field):
    """ Represents a floating point number """


@final
@dataclasses.dataclass
class Bool(Field):
    """ Represents a boolean value """


@final
@dataclasses.dataclass
class Timestamp(Field):
    """ Represents a timestamp """
    time_formats: List[str | TimestampFormat] = list
    is_event_time: bool = False


@final
@dataclasses.dataclass
class Array(Field):
    """ Represents an array of items """
    item: Field = list


@final
@dataclasses.dataclass
class Object(Field):
    """ Represents an object"""
    fields: List[Field] = list


@final
@dataclasses.dataclass
class JSON(Field):
    """ Represents a JSON object """
