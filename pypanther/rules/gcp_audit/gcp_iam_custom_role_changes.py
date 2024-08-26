from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

gcpiam_custom_role_changes_tests: list[RuleTest] = [
    RuleTest(
        name="Custom Role Created",
        expected_result=True,
        log={
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "status": {},
                "authenticationInfo": {
                    "principalEmail": "user.name@runpanther.io",
                    "principalSubject": "user:user.name@runpanther.io",
                },
                "requestMetadata": {
                    "callerIp": "136.24.229.58",
                    "callerSuppliedUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36,gzip(gfe)",
                    "requestAttributes": {"time": "2020-05-15T04:11:28.411897632Z", "auth": {}},
                    "destinationAttributes": {},
                },
                "serviceName": "iam.googleapis.com",
                "methodName": "google.iam.admin.v1.CreateRole",
                "authorizationInfo": [
                    {
                        "resource": "projects/western-verve-123456",
                        "permission": "iam.roles.create",
                        "granted": True,
                        "resourceAttributes": {},
                    },
                ],
                "resourceName": "projects/western-verve-123456/roles/CustomRole",
                "serviceData": {
                    "@type": "type.googleapis.com/google.iam.admin.v1.AuditData",
                    "permissionDelta": {
                        "addedPermissions": [
                            "apigee.apiproducts.create",
                            "apigee.apiproducts.delete",
                            "apigee.apiproducts.get",
                        ],
                    },
                },
                "request": {
                    "parent": "projects/western-verve-123456",
                    "role": {
                        "stage": 1,
                        "included_permissions": [
                            "apigee.apiproducts.create",
                            "apigee.apiproducts.delete",
                            "apigee.apiproducts.get",
                        ],
                        "title": "Jack's custom role",
                        "description": "Created on: 2020-05-14",
                    },
                    "@type": "type.googleapis.com/google.iam.admin.v1.CreateRoleRequest",
                    "role_id": "CustomRole",
                },
                "response": {
                    "name": "projects/western-verve-123456/roles/CustomRole",
                    "group_title": "Custom",
                    "title": "Jack's custom role",
                    "included_permissions": [
                        "apigee.apiproducts.create",
                        "apigee.apiproducts.delete",
                        "apigee.apiproducts.get",
                    ],
                    "@type": "type.googleapis.com/google.iam.admin.v1.Role",
                    "description": "Created on: 2020-05-14",
                    "group_name": "custom",
                    "etag": "BwWlqAHm9IY=",
                    "stage": 1,
                },
            },
            "insertId": "y4nffme2rory",
            "resource": {
                "type": "iam_role",
                "labels": {
                    "project_id": "western-verve-123456",
                    "role_name": "projects/western-verve-123456/roles/CustomRole",
                },
            },
            "timestamp": "2020-05-15T04:11:28.224558457Z",
            "severity": "NOTICE",
            "logName": "projects/western-verve-123456/logs/cloudaudit.googleapis.com%2Factivity",
            "receiveTimestamp": "2020-05-15T04:11:29.472913078Z",
        },
    ),
]


@panther_managed
class GCPIAMCustomRoleChanges(Rule):
    id = "GCP.IAM.CustomRoleChanges-prototype"
    display_name = "GCP IAM Role Has Changed"
    dedup_period_minutes = 1440
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP", "Identity & Access Management", "Privilege Escalation:Valid Accounts"]
    reports = {"CIS": ["2.6"], "MITRE ATT&CK": ["TA0004:T1078"]}
    default_severity = Severity.INFO
    default_description = "A custom role has been created, deleted, or updated."
    default_runbook = "No action needed, informational"
    default_reference = "https://cloud.google.com/iam/docs/creating-custom-roles"
    summary_attributes = ["severity", "p_any_ip_addresses", "p_any_domain_names"]
    tests = gcpiam_custom_role_changes_tests
    ROLE_METHODS = {
        "google.iam.admin.v1.CreateRole",
        "google.iam.admin.v1.DeleteRole",
        "google.iam.admin.v1.UpdateRole",
    }

    def rule(self, event):
        return (
            deep_get(event, "resource", "type") == "iam_role"
            and deep_get(event, "protoPayload", "methodName") in self.ROLE_METHODS
        )

    def dedup(self, event):
        return deep_get(event, "resource", "labels", "project_id", default="<UNKNOWN_PROJECT>")
