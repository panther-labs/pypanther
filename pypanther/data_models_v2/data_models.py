import abc
from enum import Enum
from typing import List

from pypanther import PantherLogType


class FieldType(Enum, str):
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


class FieldMapping:
    """Represents a field mapping in a data model."""
    log_type: PantherLogType | str
    """The log type that this field belongs to."""
    # TODO: Right now we support field_paths but we should be able to support transformations as well
    # TODO: This could be pointing to a schema attribute in the log type
    field_path: str
    """The path to the field in the log."""

    @classmethod
    def as_dict(cls) -> dict[str, any]:
        return {
            "log_type": cls.log_type,
            "field_path": cls.field_path
        }


class Field:
    """Represents a field in a data model."""
    name: str
    """The name of the field. This is the key that will be used to access the field in the data model."""
    description: str = ""
    """A description of the field."""
    type_: FieldType
    """The type of the field."""
    mappings: List[FieldMapping]
    """Mappings describe how the data model field is derived from the various log types."""

    @classmethod
    def as_dict(cls)-> dict[str, any]:
        return {
            "name": cls.name,
            "description": cls.description,
            "type": cls.type_,
            "mappings": [mapping.as_dict() for mapping in cls.mappings]
        }


class DataModel(metaclass=abc.ABCMeta):
    """A Panther data model. This class should be subclassed to create a new Data Model."""
    id_: str
    """The unique identifier of the data model."""
    description: str = ""
    """A description of the data model."""
    enabled: bool = True
    """Whether the data model is enabled can can be used."""
    fields: List[Field]
    """The fields that make up the data model."""

    @classmethod
    def is_panther_managed(cls) -> bool:
        return cls.__module__.startswith("pypanther")

    @classmethod
    def as_dict(cls) -> dict[str, any]:
        return {
            "id": cls.id_,
            "description": cls.description,
            "enabled": cls.enabled,
            "fields": [field.as_dict() for field in cls.fields]
        }
