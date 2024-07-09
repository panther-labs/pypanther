import abc
import dataclasses
import datetime
from typing import Optional, Any

from .field import new_string, new_timestamp, TimestampFormat, new_object, new_json


@dataclasses.dataclass
class SplitTransform:
    from_field: str
    separator: str
    index: int


class PantherParser(abc.ABCMeta):
    # TODO: Implement this class
    pass


class PantherParserCSV(PantherParser):
    # TODO: Implement this class
    has_header: bool = True
    delimiter: str = ","


class Schema(abc.ABCMeta):

    @abc.abstractmethod
    def _description(cls) -> Optional[str]:
        pass

    @abc.abstractmethod
    def _archived(cls) -> bool:
        pass


class EKSAudit(Schema):
    def _parser(cls) -> Optional[PantherParser]:
        return None

    def _description(cls) -> Optional[str]:
        return "Schema for EKS audit logs"

    def _archived(cls) -> bool:
        return False

    annotations: Any = new_json(description="The annotations of the event")
    eventTime: datetime.time = new_timestamp(
        description="The timestamp of the event",
        time_formats=[TimestampFormat.RFC3339],
        is_event_time=True)
    sourceIPAddress: str = new_string(
        description="The source IP address of the event")
    requestParameters: Any = new_json(
        description="The request parameters of the event")
    responseElements = new_json(
        description="The response elements of the event")
    additionalEventData = new_object(
        description="The additional event data of the event")
