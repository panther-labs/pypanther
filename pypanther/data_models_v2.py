import abc
import copy
import dataclasses
from enum import Enum
from typing import List, Optional

from pypanther import PantherLogType

"""This file contains data model definitions for the PyPanther package.
It is still in development and is subject to change.
"""

DATA_MODEL_ALL_ATTRS = [
    "data_model_id",
    "description",
    "enabled",
    "fields",
]


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


@dataclasses.dataclass
class FieldMapping:
    """Represents a field mapping in a data model."""

    log_type: PantherLogType | str
    """The log type that this field belongs to."""
    # TODO: Right now we support field_paths but we should be able to support transformations as well
    # TODO: This could be pointing to a schema attribute in the log type
    field_path: str
    """The path to the field in the log."""


@dataclasses.dataclass
class Field:
    """Represents a field in a data model."""

    name: str
    field_type: FieldType
    """The type of the field."""
    """The name of the field. This is the key that will be used to access the field in the data model."""
    mappings: List[FieldMapping]
    """Mappings describe how the data model field is derived from the various log types."""
    description: str = ""
    """A description of the field."""


class DataModel(abc.ABC):
    """A Panther data model. This class should be subclassed to create a new Data Model."""

    data_model_id: str
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
    def override(
        cls,
        data_model_id: Optional[str] = None,
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
        """Creates a copy of all class attributes to avoid modifications affecting parent.fields.
        child.fields.append(Field("foo",...))
        parent.fields.append(Field("foo",...) # not inherited by children of parent
        """
        for attr in DATA_MODEL_ALL_ATTRS:
            if attr not in cls.__dict__:
                try:
                    v = getattr(cls, attr)
                except AttributeError:
                    v = None

                if v is not None:
                    setattr(cls, attr, copy.deepcopy(v))
        super().__init_subclass__(**kwargs)
