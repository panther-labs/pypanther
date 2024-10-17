from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPcomputeinstancescreatePrivilegeEscalation(Rule):
    log_types = [LogType.GCP_AUDIT_LOG]
    default_description = "Detects compute.instances.create method for privilege escalation in GCP."
    display_name = "GCP compute.instances.create Privilege Escalation"
    id = "GCP.compute.instances.create.Privilege.Escalation-prototype"
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    default_runbook = "Confirm this was authorized and necessary behavior."
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    default_severity = Severity.HIGH
    REQUIRED_PERMISSIONS = [
        "compute.disks.create",
        "compute.instances.create",
        "compute.instances.setMetadata",
        "compute.instances.setServiceAccount",
        "compute.subnetworks.use",
        "compute.subnetworks.useExternalIp",
    ]

    def rule(self, event):
        if event.deep_get("protoPayload", "response", "error"):
            return False
        method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
        if not method.endswith("compute.instances.insert"):
            return False
        authorization_info = event.deep_get("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        granted_permissions = {}
        for auth in authorization_info:
            granted_permissions[auth["permission"]] = auth["granted"]
        for permission in self.REQUIRED_PERMISSIONS:
            if not granted_permissions.get(permission):
                return False
        return True

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        service_accounts = event.deep_get("protoPayload", "request", "serviceAccounts")
        if not service_accounts:
            service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
        else:
            service_account_emails = [service_acc["email"] for service_acc in service_accounts]
        project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] created a new Compute Engine instance with [{service_account_emails}] Service Account on project [{project}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        service_accounts = event.deep_get("protoPayload", "request", "serviceAccounts")
        if not service_accounts:
            service_account_emails = "<SERVICE_ACCOUNT_EMAILS_NOT_FOUND>"
        else:
            service_account_emails = [service_acc["email"] for service_acc in service_accounts]
        context["serviceAccount"] = service_account_emails
        return context

    tests = [
        RuleTest(
            name="GCP compute.instances - Potential Privilege Escalation",
            expected_result=True,
            log={
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "some.user@company.com",
                        "principalSubject": "user:some.user@company.com",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.instances.create",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.disks.create",
                            "resource": "projects/some-project/zones/us-central1-f/disks/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/disks/abc",
                                "service": "compute",
                                "type": "compute.disks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.use",
                            "resource": "projects/some-project/regions/us-central1/subnetworks/default",
                            "resourceAttributes": {
                                "name": "projects/some-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.useExternalIp",
                            "resource": "projects/some-project/regions/us-central1/subnetworks/default",
                            "resourceAttributes": {
                                "name": "projects/some-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.instances.setMetadata",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.instances.setServiceAccount",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                    ],
                    "methodName": "v1.compute.instances.insert",
                    "request": {
                        "@type": "type.googleapis.com/compute.instances.insert",
                        "disks": "...",
                        "machineType": "...",
                        "name": "...",
                        "networkInterfaces": "...",
                        "serviceAccounts": [
                            {
                                "email": "abcmail@some-project.iam.gserviceaccount.com",
                                "scopes": [
                                    "https://www.googleapis.com/auth/cloud-platform",
                                    "https://www.googleapis.com/auth/iam",
                                ],
                            },
                        ],
                    },
                    "requestMetadata": {
                        "callerIP": "1.2.3.4",
                        "callerSuppliedUserAgent": "(gzip),gzip(gfe)",
                        "destinationAttributes": {},
                        "requestAttributes": {"auth": {}, "time": "2024-01-30T12:52:36.003867Z"},
                    },
                    "resourceLocation": "...",
                    "resourceName": "projects/some-project/zones/us-central1-f/instances/abc",
                    "response": {
                        "@type": "type.googleapis.com/operation",
                        "id": "8758546889396539388",
                        "insertTime": "2024-01-30T04:52:35.886-08:00",
                        "name": "operation-1706619154623-610293c7a6a25-934f1c35-1efebb12",
                        "operationType": "insert",
                        "progress": "0",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/some-project/zones/us-central1-f/operations/operation-1706619154623-610293c7a6a25-934f1c35-1efebb12",
                        "selfLinkWithId": "https://www.googleapis.com/compute/v1/projects/some-project/zones/us-central1-f/operations/8758546889396539388",
                        "startTime": "2024-01-30T04:52:35.887-08:00",
                        "status": "RUNNING",
                        "targetId": "1454427709413609468",
                        "targetLink": "https://www.googleapis.com/compute/v1/projects/some-project/zones/us-central1-f/instances/abc",
                        "user": "some.user@company.com",
                        "zone": "https://www.googleapis.com/compute/v1/projects/some-project/zones/us-central1-f",
                    },
                    "serviceName": "compute.googleapis.com",
                },
                "receiveTimestamp": "2024-01-30 12:52:36.642422049",
                "resource": {
                    "labels": {
                        "instance_id": "1454427709413609468",
                        "project_id": "some-project",
                        "zone": "us-central1-f",
                    },
                    "type": "gce_instance",
                },
                "severity": "NOTICE",
                "timestamp": "2024-01-30 12:52:34.676384000",
            },
        ),
        RuleTest(
            name="GCP compute.instances - Error",
            expected_result=False,
            log={
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "some.user@company.com",
                        "principalSubject": "user:some.user@company.com",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.instances.create",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.disks.create",
                            "resource": "projects/some-project/zones/us-central1-f/disks/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/disks/abc",
                                "service": "compute",
                                "type": "compute.disks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.use",
                            "resource": "projects/some-project/regions/us-central1/subnetworks/default",
                            "resourceAttributes": {
                                "name": "projects/some-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.useExternalIp",
                            "resource": "projects/some-project/regions/us-central1/subnetworks/default",
                            "resourceAttributes": {
                                "name": "projects/some-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.instances.setMetadata",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.instances.setServiceAccount",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                    ],
                    "methodName": "v1.compute.instances.insert",
                    "request": {
                        "@type": "...",
                        "disks": "...",
                        "machineType": "...",
                        "name": "...",
                        "networkInterfaces": "...",
                        "serviceAccounts": [
                            {
                                "email": "abcmail@some-project.iam.gserviceaccount.com",
                                "scopes": [
                                    "https://www.googleapis.com/auth/cloud-platform",
                                    "https://www.googleapis.com/auth/iam",
                                ],
                            },
                        ],
                    },
                    "requestMetadata": "...",
                    "resourceLocation": "...",
                    "resourceName": "projects/some-project/zones/us-central1-f/instances/abc",
                    "response": {
                        "@type": "type.googleapis.com/error",
                        "error": {
                            "code": 404,
                            "errors": [
                                {
                                    "domain": "global",
                                    "message": "The resource 'abc' was not found",
                                    "reason": "notFound",
                                },
                            ],
                            "message": "The resource 'abc' was not found",
                        },
                    },
                    "serviceName": "compute.googleapis.com",
                    "status": {"code": 5, "message": "The resource 'abc' was not found"},
                },
                "receiveTimestamp": "2024-01-30 11:03:56.719662927",
                "resource": {
                    "labels": {"instance_id": "", "project_id": "some-project", "zone": "us-central1-f"},
                    "type": "gce_instance",
                },
                "severity": "ERROR",
                "timestamp": "2024-01-30 11:03:55.700872000",
            },
        ),
        RuleTest(
            name="GCP compute.instances - Not All Permissions",
            expected_result=False,
            log={
                "protoPayload": {
                    "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {
                        "principalEmail": "some.user@company.com",
                        "principalSubject": "user:some.user@company.com",
                    },
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "compute.instances.create",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.disks.create",
                            "resource": "projects/some-project/zones/us-central1-f/disks/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/disks/abc",
                                "service": "compute",
                                "type": "compute.disks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.use",
                            "resource": "projects/some-project/regions/us-central1/subnetworks/default",
                            "resourceAttributes": {
                                "name": "projects/some-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.subnetworks.useExternalIp",
                            "resource": "projects/some-project/regions/us-central1/subnetworks/default",
                            "resourceAttributes": {
                                "name": "projects/some-project/regions/us-central1/subnetworks/default",
                                "service": "compute",
                                "type": "compute.subnetworks",
                            },
                        },
                        {
                            "granted": True,
                            "permission": "compute.instances.setMetadata",
                            "resource": "projects/some-project/zones/us-central1-f/instances/abc",
                            "resourceAttributes": {
                                "name": "projects/some-project/zones/us-central1-f/instances/abc",
                                "service": "compute",
                                "type": "compute.instances",
                            },
                        },
                    ],
                    "methodName": "v1.compute.instances.insert",
                    "request": "...",
                    "requestMetadata": "...",
                    "resourceLocation": "...",
                    "resourceName": "...",
                    "response": "...",
                    "serviceName": "...",
                },
                "receiveTimestamp": "...",
                "resource": "...",
            },
        ),
    ]
