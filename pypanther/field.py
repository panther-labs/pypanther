import abc
from enum import Enum
from typing import List, Optional


class PantherFieldType(Enum):
    STRING = "string"
    INT = "int"
    SMALLINT = "smallint"
    BIGINT = "bigint"
    FLOAT = "float"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    ARRAY = "array"
    OBJECT = "object"


class PantherTimestampFormat(Enum):
    RFC3339 = "rfc3339"
    UNIX_AUTO = "unix_auto"
    UNIX = "unix"
    UNIX_MS = "unix_ms"
    UNIX_NS = "unix_ns"
    UNIX_US = "unix_us"


class PantherField(metaclass=abc.ABCMeta):
    Name: str
    Description: Optional[str] = None
    Required: bool = False
    Type: PantherFieldType


class PantherFieldString(PantherField):
    def __init__(self, name: str,
                 description: str = None,
                 required: bool = False):
        self.Name = name
        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.STRING


class PantherFieldInt(PantherField):
    def __init__(self, name: str,
                 description: str = None,
                 required: bool = False):
        self.Name = name
        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.INT


class PantherFieldBigInt(PantherField):
    def __init__(self, name: str,
                 description: str = None,
                 required: bool = False):
        self.Name = name
        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.BIGINT


class PantherFieldFloat(PantherField):
    def __init__(self, name: str,
                 description: str = None,
                 required: bool = False):
        self.Name = name
        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.FLOAT


class PantherFieldBoolean(PantherField):
    def __init__(self, name: str,
                 description: str = None,
                 required: bool = False):
        self.Name = name
        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.BOOLEAN


class PantherFieldTimestamp(PantherField):
    TimeFormats: List[str] = []
    IsEventTime: bool = False

    def __init__(self, name: str,
                 time_formats: List[str | PantherTimestampFormat],
                 description: str = None,
                 required: bool = False,
                 is_event_time: bool = False):
        self.Name = name
        self.Description = description
        self.Type = PantherFieldType.TIMESTAMP
        self.TimeFormats = time_formats
        self.IsEventTime = is_event_time
        self.Required = required


class PantherFieldArray(PantherField):
    Array: List[PantherField] = []

    def __init__(self, name: str,
                 array: List[PantherField],
                 description: str = None,
                 required: bool = False,
                 ):
        self.Name = name
        self.Description = description
        self.Type = PantherFieldType.ARRAY
        self.Required = required
        self.Array = array


class PantherFieldObject(PantherField):
    Fields: List[PantherField]

    def __init__(self, name: str,
                 fields: List[PantherField],
                 description: str = None,
                 required: bool = False):
        self.Name = name

        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.OBJECT


class PantherFieldJson(PantherField):
    def __init__(self, name: str,
                 description: str = None,
                 required: bool = False):
        self.Name = name
        self.Description = description
        self.Required = required
        self.Type = PantherFieldType.OBJECT
