import json
from fnmatch import fnmatch
from typing import List

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import PantherDataModel, PantherDataModelMapping
from pypanther.helpers.panther_base_helpers import deep_get, get_binding_deltas
from pypanther.log_types import PantherLogType

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
    id_: str = "Standard.GCP.AuditLog"
    display_name: str = "GCP Audit Log"
    enabled: bool = True
    log_types: List[str] = [PantherLogType.GCP_AuditLog]
    mappings: List[PantherDataModelMapping] = [
        PantherDataModelMapping(
            name="actor_user", path="$.protoPayload.authenticationInfo.principalEmail"
        ),
        PantherDataModelMapping(name="assigned_admin_role", method=get_iam_roles),
        PantherDataModelMapping(name="event_type", method=get_event_type),
        PantherDataModelMapping(name="source_ip", path="$.protoPayload.requestMetadata.callerIP"),
        PantherDataModelMapping(name="user", method=get_modified_users),
        PantherDataModelMapping(name="annotations", path="$.labels"),
        PantherDataModelMapping(name="apiGroup", method=get_api_group),
        PantherDataModelMapping(name="apiVersion", method=get_api_version),
        PantherDataModelMapping(name="namespace", method=get_namespace),
        PantherDataModelMapping(name="resource", method=get_resource),
        PantherDataModelMapping(name="name", method=get_name),
        PantherDataModelMapping(name="requestURI", method=get_request_uri),
        PantherDataModelMapping(name="responseStatus", path="$.protoPayload.status"),
        PantherDataModelMapping(name="sourceIPs", method=get_source_ips),
        PantherDataModelMapping(
            name="username", path="$.protoPayload.authenticationInfo.principalEmail"
        ),
        PantherDataModelMapping(
            name="userAgent",
            path="$.protoPayload.requestMetadata.callerSuppliedUserAgent",
        ),
        PantherDataModelMapping(name="verb", method=get_verb),
        PantherDataModelMapping(name="requestObject", path="$.protoPayload.request"),
        PantherDataModelMapping(name="responseObject", path="$.protoPayload.response"),
    ]
