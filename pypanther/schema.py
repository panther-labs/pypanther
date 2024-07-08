import abc
import dataclasses
from typing import Optional

from .field import String, Timestamp, TimestampFormat, Object, JSON, Bool, Array


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
    def _parser(cls) -> Optional[PantherParser]:
        pass

    @abc.abstractmethod
    def _description(cls) -> Optional[str]:
        pass

    @abc.abstractmethod
    def _archived(cls) -> bool:
        pass


class CustomSchemaOne(Schema):
    id: str
    name: str


class MyClassTwo(Schema):
    id: str
    name: str
    description: str


class EKSAudit(Schema):
    def _parser(cls) -> Optional[PantherParser]:
        return None

    def _description(cls) -> Optional[str]:
        return "Schema for EKS audit logs"

    def _archived(cls) -> bool:
        return False

    annotations = JSON(
        description="The annotations of the event",
        required=True)
    eventTime = Timestamp(
        description="The timestamp of the event",
        time_formats=[TimestampFormat.RFC3339],
        is_event_time=True)
    sourceIPAddress = String(
        description="The source IP address of the event",
        required=True)
    userAgent = String(description="The user agent of the event",required=True)
    requestParameters = JSON(
        description="The request parameters of the event",
        required=True)
    responseElements = Object(
        description="The response elements of the event",
        required=True)
    eventID = String(
        description="The event ID of the event",
        required=True)
    eventName = String(
        description="The event name of the event",
        required=True)
    awsRegion = String(
        description="The AWS region of the event",
        required=True)
    errorCode = String(
        description="The error code of the event",
        required=True)
    errorMessage = String(
        description="The error message of the event",
        required=True)
    requestID = String(
        description="The request ID of the event",
        required=True)
    eventSource = String(
        description="The event source of the event",
        required=True)
    eventVersion = String(
        description="The event version of the event",
        required=True)
    userIdentity = Object(
        description="The user identity of the event",
        required=True)
    recipientAccountId = String(
        description="The recipient account ID of the event",
        required=True)
    eventCategory = String(
        description="The event category of the event",
        required=True)
    eventType = String(
        description="The event type of the event",
        required=True)
    apiVersion = String(
        description="The API version of the event",
        required=True)
    managementEvent = Bool(
        description="The management event of the event",
        required=True)
    readOnly = Bool(
        description="The read only status of the event",
        required=True)
    resources = Array(
        description="The resources of the event",
        required=True,
        item=Object(
            description="The resource of the event",
            required=True))
    additionalEventData = Object(
        description="The additional event data of the event",
        required=True)


class GCPAudit(Schema):

    def _parser(cls) -> Optional[PantherParser]:
        return None

    def _description(cls) -> Optional[str]:
        return "Schema for GCP audit logs"

    def _archived(cls) -> bool:
        return False

    eventTime = Timestamp(
        description="The timestamp of the event",
        time_formats=[TimestampFormat.RFC3339],
        is_event_time=True)

    serviceName = String(
        description="The service name of the event",
        required=True)

    methodName = String(
        description="The method name of the event",
        required=True)

    resourceName = String(
        description="The resource name of the event",
        required=True)

    resourceType = String(
        description="The resource type of the event",
        required=True)

    request = JSON(
        description="The request of the event",
        required=True)

    response = JSON(
        description="The response of the event",
        required=True)