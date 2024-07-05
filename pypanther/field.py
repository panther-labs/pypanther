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


@dataclasses.dataclass
class Field(metaclass=abc.ABCMeta):
    Description: Optional[str] = None
    Required: bool = False

    @property
    @abc.abstractmethod
    def Type(self) -> FieldType:
        raise NotImplementedError("You must implement the rule method in your rule class.")


@final
@dataclasses.dataclass
class String(Field):
    def Type(self) -> FieldType:
        return FieldType.STRING


@final
@dataclasses.dataclass
class Int(Field):
    def Type(self) -> FieldType:
        return FieldType.INT


@final
@dataclasses.dataclass
class BigInt(Field):
    def Type(self) -> FieldType:
        return FieldType.BIGINT


@final
@dataclasses.dataclass
class Float(Field):
    def Type(self) -> FieldType:
        return FieldType.FLOAT


@final
@dataclasses.dataclass
class Bool(Field):
    def Type(self) -> FieldType:
        return FieldType.BOOLEAN


@final
@dataclasses.dataclass
class Timestamp(Field):
    TimeFormats: List[str | TimestampFormat] = list
    IsEventTime: bool = False

    def Type(self) -> FieldType:
        return FieldType.TIMESTAMP


@final
@dataclasses.dataclass
class Array(Field):
    Array: List[Field] = list

    def Type(self) -> FieldType:
        return FieldType.ARRAY


@final
@dataclasses.dataclass
class Object(Field):
    Fields: List[Field] = list

    def Type(self) -> FieldType:
        return FieldType.OBJECT


@final
@dataclasses.dataclass
class Json(Field, Any):
    def Type(self) -> FieldType:
        return FieldType.JSON
