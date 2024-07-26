from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Optional, List, TypeVar, Generic

from pypanther import LogType


class FieldType(str, Enum):
    """Enumeration of all possible field types."""

    STRING = "string"
    SMALL_INT = "smallint"
    BIG_INT = "bigint"
    FLOAT = "float"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    ARRAY = "array"
    OBJECT = "object"
    JSON = "json"


@dataclass
class FieldMapping:
    log_type: LogType
    field_path: str


T = TypeVar('T')


@dataclass
class Field(Generic[T]):
    description: str
    type: FieldType
    mappings: List[FieldMapping]
    value: Optional[T] = None

    def __set__(self, instance, value):
        self.value = value


def new_string(description: str, mappings: List[FieldMapping]) -> Field[str]:
    return Field[str](description, FieldType.STRING, mappings)


def new_smallint(description: str, mappings: List[FieldMapping]) -> Field[int]:
    return Field[int](description, FieldType.SMALL_INT, mappings)


def new_bigint(description: str, mappings: List[FieldMapping]) -> Field[int]:
    return Field[int](description, FieldType.BIG_INT, mappings)


def new_float(description: str, mappings: List[FieldMapping]) -> Field[float]:
    return Field[float](description, FieldType.FLOAT, mappings)


def new_boolean(description: str, mappings: List[FieldMapping]) -> Field[bool]:
    return Field[bool](description, FieldType.FLOAT, mappings)


def new_json(description: str, mappings: List[FieldMapping]) -> Field[Any]:
    return Field[Any](description, FieldType.JSON, mappings)


class DataModelMeta(type):

    def __new__(cls, name, bases, attrs):
        fields: dict[str, Field] = {}
        for key, value in attrs.items():
            if isinstance(value, Field):
                fields[key] = value
        new_class = super().__new__(cls, name, bases, attrs)
        new_class._fields = fields
        return new_class


class DataModel(metaclass=DataModelMeta):
    _fields: Dict[str, Field] = {}
    p_raw_event: Dict[str, Any] = {}

    def __init__(self, raw_data: Dict[str, Any]):
        self.p_raw_event = raw_data
        self._populate_fields()

    def _populate_fields(self):
        for field_name, field in self._fields.items():
            for mapping in field.mappings:
                value = self.p_raw_event.get(mapping.field_path)
                field.value = value

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if isinstance(attr, Field):
            return attr.value
        return attr

