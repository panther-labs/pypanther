import json
from fnmatch import fnmatch
from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get, get_binding_deltas
from pypanther.log_types import LogType

ADMIN_ROLES = {
    # Primitive Rolesx
    "roles/owner",
    # Predefined Roles
    "roles/*Admin",
}


def get_event_type(event):
    # currently, only tracking a handful of event types
    for delta in get_binding_deltas(event):
        if delta["action"] == "ADD":
            if any(
                (
                    fnmatch(delta.get("role", ""), admin_role_pattern)
                    for admin_role_pattern in ADMIN_ROLES
                )
            ):
                return event_type.ADMIN_ROLE_ASSIGNED

    return None


def get_admin_map(event):
    roles_assigned = {}
    for delta in get_binding_deltas(event):
        if delta.get("action") == "ADD":
            roles_assigned[delta.get("member")] = delta.get("role")

    return roles_assigned


def get_modified_users(event):
    event_dict = event.to_dict()
    roles_assigned = get_admin_map(event_dict)

    return json.dumps(list(roles_assigned.keys()))


def get_iam_roles(event):
    event_dict = event.to_dict()
    roles_assigned = get_admin_map(event_dict)

    return json.dumps(list(roles_assigned.values()))


def get_api_group(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[0]
    except IndexError:
        return ""


def get_api_version(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[1]
    except IndexError:
        return ""


def get_namespace(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[3]
    except IndexError:
        return ""


def get_resource(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[4]
    except IndexError:
        return ""


def get_name(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[5]
    except IndexError:
        return ""


def get_request_uri(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    return "/apis/" + deep_get(event, "protoPayload", "resourceName", default="")


def get_source_ips(event):
    caller_ip = deep_get(event, "protoPayload", "requestMetadata", "callerIP", default=None)
    if caller_ip:
        return [caller_ip]
    return []


def get_verb(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    return deep_get(event, "protoPayload", "methodName", default="").split(".")[-1]


class StandardGCPAuditLog(PantherDataModel):
    DataModelID: str = "Standard.GCP.AuditLog"
    DisplayName: str = "GCP Audit Log"
    Enabled: bool = True
    LogTypes: List[str] = [LogType.GCP_AuditLog]
    Mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(
            Name="actor_user", Path="$.protoPayload.authenticationInfo.principalEmail"
        ),
        PantherDataModelMapping(Name="assigned_admin_role", Method=get_iam_roles),
        PantherDataModelMapping(Name="event_type", Method=get_event_type),
        PantherDataModelMapping(Name="source_ip", Path="$.protoPayload.requestMetadata.callerIP"),
        PantherDataModelMapping(Name="user", Method=get_modified_users),
        PantherDataModelMapping(Name="annotations", Path="$.labels"),
        PantherDataModelMapping(Name="apiGroup", Method=get_api_group),
        PantherDataModelMapping(Name="apiVersion", Method=get_api_version),
        PantherDataModelMapping(Name="namespace", Method=get_namespace),
        PantherDataModelMapping(Name="resource", Method=get_resource),
        PantherDataModelMapping(Name="name", Method=get_name),
        PantherDataModelMapping(Name="requestURI", Method=get_request_uri),
        PantherDataModelMapping(Name="responseStatus", Path="$.protoPayload.status"),
        PantherDataModelMapping(Name="sourceIPs", Method=get_source_ips),
        PantherDataModelMapping(
            Name="username", Path="$.protoPayload.authenticationInfo.principalEmail"
        ),
        PantherDataModelMapping(
            Name="userAgent", Path="$.protoPayload.requestMetadata.callerSuppliedUserAgent"
        ),
        PantherDataModelMapping(Name="verb", Method=get_verb),
        PantherDataModelMapping(Name="requestObject", Path="$.protoPayload.request"),
        PantherDataModelMapping(Name="responseObject", Path="$.protoPayload.response"),
    ]
