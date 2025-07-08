from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPComputeSSHConnection(Rule):
    id = "GCP.Compute.SSHConnection-prototype"
    display_name = "GCP Compute SSH Connection"
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.INFO
    default_description = "Detect any SSH connections to a Compute Instance.\n"
    default_reference = "https://cloud.google.com/compute/docs/connect/ssh-best-practices/auditing\n"
    tags = ["GCP", "GCP.AuditLog", "SSH", "Compute", "Beta"]

    def rule(self, event: PantherEvent) -> bool:
        service_name = event.deep_get("protoPayload", "serviceName", default="")
        method_name = event.deep_get("protoPayload", "methodName", default="")
        if service_name == "iap.googleapis.com" and method_name == "AuthorizeUser":
            return True
        if service_name == "oslogin.googleapis.com":
            if any([method_name.endswith(".CheckPolicy"), method_name.endswith(".ContinueSession")]):
                return True
        if service_name == "compute.googleapis.com":
            # Check attempts to add SSH keys to the VM
            # setCommonInstanceMetadata is triggered when SSHing from a remote device
            # setMetadata is triggered when SSHing from the GCP Console
            ssh_keys = {"ssh-keys", "sshKeys"}  # Fields indicating the SSH keys were modified
            if any([method_name.endswith(".setCommonInstanceMetadata"), method_name.endswith(".setMetadata")]):
                # The metadata delta field could be for the project or the instance, and could indicate
                # something was removed or modified. We need to check all possible paths to the field
                # we need.
                modified_keys = set()
                for field1 in ["projectMetadataDelta", "instanceMetadataDelta"]:
                    for field2 in ["addedMetadataKeys", "modifiedMetadataKeys"]:
                        modified_keys.update(
                            set(event.deep_get("protoPayload", "metadata", field1, field2, default=[])),
                        )
                return bool(modified_keys & ssh_keys)
        # Check direct connections to the serial console
        # The actual service name has the region included, so we just so an easy check here
        if service_name.endswith("ssh-serialport.googleapis.com"):
            if method_name == "google.ssh-serialport.v1.connect":
                return "succeeded" in event.deep_get("protoPayload", "status", "message", default="").lower()
        return False

    def alert_context(self, event: PantherEvent) -> dict:
        instance_info = self.get_instance_info(event)
        context = {
            "instance_id": instance_info.get("id", "UNKNOWN INSTANCE ID"),
            "instance_name": instance_info.get("name", "UNKNOWN INSTANCE NAME"),
        }
        return gcp_alert_context(event) | context

    def get_instance_info(self, event: PantherEvent) -> dict:
        service_name = event.deep_get("protoPayload", "serviceName", default="")
        context = {"id": "UNKNOWN INSTANCE ID", "name": "UNKNOWN INSTANCE NAME"}
        # Name is not included in the event
        match service_name:
            case "iap.googleapis.com":
                context |= {"id": event.deep_get("resource", "labels", "instance_id", default="UNKNOWN INSTANCE ID")}
            case "oslogin.googleapis.com":
                context |= {
                    "id": event.deep_get("labels", "instance_id", default="UNKNOWN INSTANCE ID"),
                    "name": event.deep_get("protoPayload", "request", "instance", default="UNKNOWN INSTANCE NAME"),
                }
            case "compute.googleapis.com":
                if event.deep_get("protoPayload", "methodName", default="").endswith(".setCommonInstanceMetadata"):
                    # These events are targeted prokect-wide, so they don't have information about
                    # specific instances.
                    pass
                else:
                    # Will look like: projects/project-name/zones/zone-name/instances/instance-name
                    context |= {
                        "name": event.deep_get("protoPayload", "resourceName", default="/UNKNOWN INSTANCE NAME").split(
                            "/",
                        )[-1],
                    }
        if "serialport" in service_name:
            # Will look like:
            # projects/projectName/zones/zoneName/instances/instanceName/SerialPort/portNum
            context |= {
                "id": event.deep_get("resource", "labels", "instance_id", default="UNKNOWN INSTANCE ID"),
                "name": event.deep_get("protoPayload", "resourceName", default="/UNKNOWN INSTANCE NAME//").split("/")[
                    -3
                ],
            }
        return context

    tests = [
        RuleTest(
            name="Connect with IAP",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["192.168.1.100"],
                "p_any_emails": ["user@example.com"],
                "p_any_usernames": ["user"],
                "p_event_time": "2025-05-27 16:46:46.485356507",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2025-05-27 19:05:21.311995228",
                "p_row_id": "fee0f92d7864a191dfa994e326d28304",
                "p_schema_version": 0,
                "p_source_id": "bd7da315-647e-4eca-bcfe-083fab18f3f1",
                "p_source_label": "gcp-logsource",
                "p_udm": {
                    "source": {"address": "192.168.1.100", "ip": "192.168.1.100"},
                    "user": {"email": "user@example.com"},
                },
                "insertId": "1rk2tche2xh0e",
                "logName": "projects/example-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "operation": {"id": "Q444-UYUD-GBRY-QFUF-AS7Q-6A6E", "producer": "iap.googleapis.com"},
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@example.com"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iap.tunnelInstances.accessViaIAP",
                            "resource": "projects/123456789012/iap_tunnel/zones/us-central1-f/instances/1234567890123456789",
                            "resourceAttributes": {
                                "name": "projects/123456789012/iap_tunnel/zones/us-central1-f/instances/1234567890123456789",
                                "service": "iap.googleapis.com",
                                "type": "iap.googleapis.com/TunnelInstance",
                            },
                        },
                    ],
                    "metadata": {
                        "device_id": "",
                        "device_state": "Unknown",
                        "iap_tcp_session_info": {"bytes_received": 6922, "bytes_sent": 2874, "phase": "SESSION_END"},
                        "oauth_client_id": "",
                        "request_id": "1640143122448486764",
                    },
                    "methodName": "AuthorizeUser",
                    "request": {
                        "@type": "type.googleapis.com/cloud.security.gatekeeper.AuthorizeUserRequest",
                        "httpRequest": {"url": ""},
                    },
                    "requestMetadata": {
                        "callerIP": "192.168.1.100",
                        "callerSuppliedUserAgent": "(none supplied)",
                        "destinationAttributes": {"ip": "10.128.0.9", "port": "22"},
                        "requestAttributes": {"auth": {}, "time": "2025-05-27T16:46:46.500915047Z"},
                    },
                    "resourceName": "1234567890123456789",
                    "serviceName": "iap.googleapis.com",
                    "status": {},
                },
                "receiveTimestamp": "2025-05-27 16:46:48.028847516",
                "resource": {
                    "labels": {
                        "instance_id": "1234567890123456789",
                        "project_id": "example-project",
                        "zone": "us-central1-f",
                    },
                    "type": "gce_instance",
                },
                "severity": "INFO",
                "timestamp": "2025-05-27 16:46:46.485356507",
            },
        ),
        RuleTest(
            name="SSH From OS Login Without MFA",
            expected_result=True,
            log={
                "p_any_emails": ["user@example.com"],
                "p_any_usernames": ["user"],
                "p_event_time": "2025-05-27 21:12:08.749558000",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2025-05-27 21:15:21.194027520",
                "p_row_id": "0a634c6bfeb190d7f3b2a9e326c0d10b",
                "p_schema_version": 0,
                "p_source_id": "bd7da315-647e-4eca-bcfe-083fab18f3f1",
                "p_source_label": "gcp-logsource",
                "p_udm": {"user": {"email": "user@example.com"}},
                "insertId": "fkz9lkf10luao",
                "labels": {"instance_id": "1234567890123456789", "zone": "us-central1-f"},
                "logName": "projects/example-project/logs/cloudaudit.googleapis.com%2Fdata_access",
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@example.com"},
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "resource": "projects/example-project/zones/us-central1-f/instances/example-instance",
                        },
                    ],
                    "methodName": "google.cloud.oslogin.dataplane.OsLoginDataPlaneService.CheckPolicy",
                    "request": {
                        "@type": "type.googleapis.com/google.cloud.oslogin.dataplane.CheckPolicyRequest",
                        "email": "123456789012345678901",
                        "instance": "example-instance",
                        "numericProjectId": "123456789012",
                        "policy": "ADMIN_LOGIN",
                        "projectId": "example-project",
                        "serviceAccount": "example-sa@example-project.iam.gserviceaccount.com",
                        "zone": "us-central1-f",
                    },
                    "resourceName": "projects/example-project/zones/us-central1-f/instances/example-instance",
                    "response": {
                        "@type": "type.googleapis.com/google.cloud.oslogin.dataplane.CheckPolicyResponse",
                        "success": True,
                    },
                    "serviceName": "oslogin.googleapis.com",
                },
                "receiveTimestamp": "2025-05-27 21:12:09.376480048",
                "resource": {
                    "labels": {
                        "method": "google.cloud.oslogin.dataplane.OsLoginDataPlaneService.CheckPolicy",
                        "project_id": "example-project",
                        "service": "oslogin.googleapis.com",
                    },
                    "type": "audited_resource",
                },
                "severity": "INFO",
                "timestamp": "2025-05-27 21:12:08.749558000",
            },
        ),
        RuleTest(
            name="SSH From Remote Machine",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["192.168.1.100"],
                "p_any_emails": ["user@example.com"],
                "p_any_usernames": ["user"],
                "p_event_time": "2025-05-27 15:18:22.406665000",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2025-05-27 15:20:21.064927161",
                "p_row_id": "6244057f4c79ddd1c9f8d8e226939706",
                "p_schema_version": 0,
                "p_source_id": "bd7da315-647e-4eca-bcfe-083fab18f3f1",
                "p_source_label": "gcp-logsource",
                "p_udm": {
                    "source": {"address": "192.168.1.100", "ip": "192.168.1.100"},
                    "user": {"email": "user@example.com"},
                },
                "insertId": "xwyto8dyr64",
                "labels": {"compute.googleapis.com/root_trigger_id": "9cff1773-d2d3-4e20-a605-3bf753bc9dc2"},
                "logName": "projects/example-project/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "id": "operation-1748359087846-6361f925ef323-87f8ece7-5a27a574",
                    "last": True,
                    "producer": "compute.googleapis.com",
                },
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com",
                        "principalSubject": "user:user@example.com",
                    },
                    "metadata": {
                        "@type": "type.googleapis.com/google.cloud.audit.GceProjectAuditMetadata",
                        "projectMetadataDelta": {"modifiedMetadataKeys": ["ssh-keys"]},
                    },
                    "methodName": "v1.compute.projects.setCommonInstanceMetadata",
                    "request": {"@type": "type.googleapis.com/compute.projects.setCommonInstanceMetadata"},
                    "requestMetadata": {
                        "callerIP": "192.168.1.100",
                        "callerSuppliedUserAgent": "example-user-agent",
                        "destinationAttributes": {},
                        "requestAttributes": {},
                    },
                    "resourceName": "projects/example-project",
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2025-05-27 15:18:23.188347406",
                "resource": {"labels": {"project_id": "123456789012"}, "type": "gce_project"},
                "severity": "NOTICE",
                "timestamp": "2025-05-27 15:18:22.406665000",
            },
        ),
        RuleTest(
            name="SSH From GCP Console",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["192.168.1.100"],
                "p_any_emails": ["user@example.com"],
                "p_any_domain_names": ["www.googleapis.com"],
                "p_any_usernames": ["user"],
                "p_event_time": "2025-05-27 16:44:43.443688000",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2025-05-27 19:05:21.363614256",
                "p_row_id": "fee0f92d7864a191dfa994e326bb8604",
                "p_schema_version": 0,
                "p_source_id": "bd7da315-647e-4eca-bcfe-083fab18f3f1",
                "p_source_label": "gcp-logsource",
                "p_udm": {
                    "source": {"address": "192.168.1.100", "ip": "192.168.1.100"},
                    "user": {"email": "user@example.com"},
                },
                "insertId": "-6215lve1hil2",
                "labels": {"compute.googleapis.com/root_trigger_id": "f1c52ba7-0407-4ec5-b031-8f3232f828f0"},
                "logName": "projects/example-project/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "first": True,
                    "id": "operation-1748364283389-63620c80ca7f1-1f0f53ee-d1fa97bd",
                    "producer": "compute.googleapis.com",
                },
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "user@example.com",
                        "principalSubject": "user:user@example.com",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.instances.setMetadata",
                            "resource": "projects/example-project/zones/us-central1-f/instances/example-instance",
                            "resourceAttributes": {
                                "name": "projects/example-project/zones/us-central1-f/instances/example-instance",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                    ],
                    "metadata": {
                        "@type": "type.googleapis.com/google.cloud.audit.GceInstanceAuditMetadata",
                        "instanceMetadataDelta": {"addedMetadataKeys": ["ssh-keys"]},
                    },
                    "methodName": "v1.compute.instances.setMetadata",
                    "request": {"@type": "type.googleapis.com/compute.instances.setMetadata"},
                    "requestMetadata": {
                        "callerIP": "192.168.1.100",
                        "callerSuppliedUserAgent": "example-user-agent",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2025-05-27T16:44:43.801696Z"},
                    },
                    "resourceLocation": {"currentLocations": ["us-central1-f"]},
                    "resourceName": "projects/example-project/zones/us-central1-f/instances/example-instance",
                    "response": {
                        "@type": "type.googleapis.com/operation",
                        "id": "8662253207148844308",
                        "insertTime": "2025-05-27T09:44:43.751-07:00",
                        "name": "operation-1748364283389-63620c80ca7f1-1f0f53ee-d1fa97bd",
                        "operationType": "setMetadata",
                        "progress": "0",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/example-project/zones/us-central1-f/operations/operation-1748364283389-63620c80ca7f1-1f0f53ee-d1fa97bd",
                        "selfLinkWithId": "https://www.googleapis.com/compute/v1/projects/example-project/zones/us-central1-f/operations/8662253207148844308",
                        "startTime": "2025-05-27T09:44:43.768-07:00",
                        "status": "RUNNING",
                        "targetId": "1234567890123456789",
                        "targetLink": "https://www.googleapis.com/compute/v1/projects/example-project/zones/us-central1-f/instances/example-instance",
                        "user": "user@example.com",
                        "zone": "https://www.googleapis.com/compute/v1/projects/example-project/zones/us-central1-f",
                    },
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2025-05-27 16:44:44.041407158",
                "resource": {
                    "labels": {
                        "instance_id": "1234567890123456789",
                        "project_id": "example-project",
                        "zone": "us-central1-f",
                    },
                    "type": "gce_instance",
                },
                "severity": "NOTICE",
                "timestamp": "2025-05-27 16:44:43.443688000",
            },
        ),
        RuleTest(
            name="Connect to Serial Port",
            expected_result=True,
            log={
                "p_any_ip_addresses": ["192.168.1.100"],
                "p_event_time": "2025-05-27 21:27:27.208503055",
                "p_log_type": "GCP.AuditLog",
                "p_parse_time": "2025-05-27 21:30:21.036346031",
                "p_row_id": "ea1fcc08c947a6d0eab1a9e326faa309",
                "p_schema_version": 0,
                "p_source_id": "bd7da315-647e-4eca-bcfe-083fab18f3f1",
                "p_source_label": "gcp-logsource",
                "p_udm": {"source": {"address": "192.168.1.100", "ip": "192.168.1.100"}},
                "insertId": "199ms9obf4",
                "logName": "projects/example-project/logs/cloudaudit.googleapis.com%2Factivity",
                "operation": {
                    "first": True,
                    "id": "1996ae7d794305b3adac0ef09924deb467656fd2",
                    "producer": "us-central1-ssh-serialport.googleapis.com",
                },
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "methodName": "google.ssh-serialport.v1.connect",
                    "request": {
                        "@type": "type.googleapis.com/google.compute.SerialConsoleSessionBegin",
                        "serialConsoleOptions": [
                            {"name": "port", "value": "1"},
                            {"name": "source", "value": "pantheon"},
                        ],
                        "username": "user_example_com",
                    },
                    "requestMetadata": {"callerIP": "192.168.1.100"},
                    "resourceLocation": {"currentLocations": ["us-central1"], "originalLocations": ["us-central1"]},
                    "resourceName": "projects/example-project/zones/us-central1-f/instances/example-instance/SerialPort/1",
                    "serviceName": "us-central1-ssh-serialport.googleapis.com",
                    "status": {"message": "Connection succeeded."},
                },
                "receiveTimestamp": "2025-05-27 21:27:27.524944715",
                "resource": {
                    "labels": {
                        "instance_id": "1234567890123456789",
                        "project_id": "example-project",
                        "zone": "us-central1-f",
                    },
                    "type": "gce_instance",
                },
                "severity": "NOTICE",
                "timestamp": "2025-05-27 21:27:27.208503055",
            },
        ),
    ]
