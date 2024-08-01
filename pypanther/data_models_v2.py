import abc
import copy
import dataclasses
from enum import Enum
from typing import List, Optional

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


@dataclasses.dataclass
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
    "name",
    "type",
    "mappings",
    "description",
]


@dataclasses.dataclass
class Field:
    """Represents a field in a data model."""

    name: str
    """The name of the field. This is the key that will be used to access the field in the data model."""

    type: FieldType
    """The type of the field."""

    mappings: List[FieldMapping]
    """Mappings describe how the data model field is derived from the various log types."""

    description: str = ""
    """A description of the field."""

    def asdict(self):
        """Returns a dictionary representation of the instance."""
        return {key: try_asdict(getattr(self, key)) for key in _FIELD_ALL_ATTRIBUTES if hasattr(self, key)}


_DATA_MODEL_ALL_ATTRS = [
    "description",
    "enabled",
    "fields",
]


class DataModel(abc.ABC):
    """A Panther data model. This class should be subclassed to create a new Data Model."""

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
    def override(
        cls,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
        fields: Optional[List[Field]] = None,
    ):
        for key, val in locals().items():
            if key == "cls":
                continue

            if val is not None:
                setattr(cls, key, val)

    def __init_subclass__(cls, **kwargs):
        """
        Creates a copy of all class attributes to avoid modifications affecting parent.fields.
        child.fields.append(Field("foo",...))
        parent.fields.append(Field("foo",...) # not inherited by children of parent
        """
        for attr in _DATA_MODEL_ALL_ATTRS:
            if attr not in cls.__dict__:
                try:
                    v = getattr(cls, attr)
                except AttributeError:
                    v = None

                if v is not None:
                    setattr(cls, attr, copy.deepcopy(v))
        super().__init_subclass__(**kwargs)

    @classmethod
    def asdict(cls):
        """Returns a dictionary representation of the class."""
        return {key: try_asdict(getattr(cls, key)) for key in _DATA_MODEL_ALL_ATTRS if hasattr(cls, key)}
