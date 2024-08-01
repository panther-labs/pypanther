import json
from fnmatch import fnmatch

import pypanther.helpers.panther_event_type_helpers as event_type
from pypanther.base import DataModel, DataModelMapping, LogType
from pypanther.helpers.panther_base_helpers import deep_get, get_binding_deltas

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
            if any(fnmatch(delta.get("role", ""), admin_role_pattern) for admin_role_pattern in ADMIN_ROLES):
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


class StandardGCPAuditLog(DataModel):
    id: str = "Standard.GCP.AuditLog"
    display_name: str = "GCP Audit Log"
    enabled: bool = True
    log_types: list[str] = [LogType.GCP_AUDIT_LOG]
    mappings: list[DataModelMapping] = [
        DataModelMapping(name="actor_user", path="$.protoPayload.authenticationInfo.principalEmail"),
        DataModelMapping(name="assigned_admin_role", method=get_iam_roles),
        DataModelMapping(name="event_type", method=get_event_type),
        DataModelMapping(name="source_ip", path="$.protoPayload.requestMetadata.callerIP"),
        DataModelMapping(name="user", method=get_modified_users),
        DataModelMapping(name="annotations", path="$.labels"),
        DataModelMapping(name="apiGroup", method=get_api_group),
        DataModelMapping(name="apiVersion", method=get_api_version),
        DataModelMapping(name="namespace", method=get_namespace),
        DataModelMapping(name="resource", method=get_resource),
        DataModelMapping(name="name", method=get_name),
        DataModelMapping(name="requestURI", method=get_request_uri),
        DataModelMapping(name="responseStatus", path="$.protoPayload.status"),
        DataModelMapping(name="sourceIPs", method=get_source_ips),
        DataModelMapping(name="username", path="$.protoPayload.authenticationInfo.principalEmail"),
        DataModelMapping(name="userAgent", path="$.protoPayload.requestMetadata.callerSuppliedUserAgent"),
        DataModelMapping(name="verb", method=get_verb),
        DataModelMapping(name="requestObject", path="$.protoPayload.request"),
        DataModelMapping(name="responseObject", path="$.protoPayload.response"),
    ]
