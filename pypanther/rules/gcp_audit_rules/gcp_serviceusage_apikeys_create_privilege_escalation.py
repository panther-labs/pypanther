from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk
from pypanther.log_types import LogType

gc_pserviceusageapi_keyscreate_privilege_escalation_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="GCP API Key Created",
        ExpectedResult=True,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "id": "operations/akmf.p7-1028347275902-fe0c0688-44a7-4dca-bc06-8456068e5673",
                "last": True,
                "producer": "apikeys.googleapis.com",
            },
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "some.user@some-project.com",
                    "principalSubject": "serviceAccount:some-team@some-project.com",
                    "serviceAccountKeyName": "//iam.googleapis.com/projects/some-project/serviceAccounts/some-team@some-project.gserviceaccount.com/keys/dc5344c246064589v76ec76f66bafc92b093ed41",
                },
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "serviceusage.apiKeys.create",
                        "resource": "projectnumbers/1028347245602",
                        "resourceAttributes": {},
                    }
                ],
                "methodName": "google.api.apikeys.v2.ApiKeys.CreateKey",
                "request": {
                    "@type": "type.googleapis.com/google.api.apikeys.v2.CreateKeyRequest",
                    "parent": "projects/some-project/locations/global",
                },
                "requestMetadata": {
                    "callerIP": "189.163.74.177",
                    "callerSuppliedUserAgent": "(gzip),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {},
                },
                "resourceName": "projects/1028347245602",
                "response": {
                    "@type": "type.googleapis.com/google.api.apikeys.v2.Key",
                    "createTime": "1970-01-01T00:00:00Z",
                    "etag": 'W/"DSLGu9UKHwqq2ICm7YPE7g=="',
                    "name": "projects/1028347245602/locations/global/keys/bf67db25-d748-4335-ae08-7f0e65fnfy02",
                    "updateTime": "1970-01-01T00:00:00Z",
                },
                "serviceName": "apikeys.googleapis.com",
                "status": {},
            },
            "receiveTimestamp": "2024-01-25 13:28:18.961519813",
            "resource": {
                "labels": {
                    "method": "google.api.apikeys.v2.ApiKeys.CreateKey",
                    "project_id": "some-project",
                    "service": "apikeys.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2024-01-25 13:28:18.961519813",
        },
    ),
    PantherRuleTest(
        Name="GCP API Key Not Created",
        ExpectedResult=False,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "id": "operations/akmf.p7-1028347275902-fe0c0688-44a7-4dca-bc06-8456068e5673",
                "last": True,
                "producer": "apikeys.googleapis.com",
            },
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "some.user@some-project.com",
                    "principalSubject": "serviceAccount:some-team@some-project.com",
                    "serviceAccountKeyName": "//iam.googleapis.com/projects/some-project/serviceAccounts/some-team@some-project.gserviceaccount.com/keys/dc5344c246064589v76ec76f66bafc92b093ed41",
                },
                "authorizationInfo": [
                    {
                        "granted": False,
                        "permission": "serviceusage.apiKeys.create",
                        "resource": "projectnumbers/1028347245602",
                        "resourceAttributes": {},
                    }
                ],
                "methodName": "google.api.apikeys.v2.ApiKeys.CreateKey",
                "request": {
                    "@type": "type.googleapis.com/google.api.apikeys.v2.CreateKeyRequest",
                    "parent": "projects/some-project/locations/global",
                },
                "requestMetadata": {
                    "callerIP": "189.163.74.177",
                    "callerSuppliedUserAgent": "(gzip),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {},
                },
                "resourceName": "projects/1028347245602",
                "response": {
                    "@type": "type.googleapis.com/google.api.apikeys.v2.Key",
                    "createTime": "1970-01-01T00:00:00Z",
                    "etag": 'W/"DSLGu9UKHwqq2ICm7YPE7g=="',
                    "name": "projects/1028347245602/locations/global/keys/bf67db25-d748-4335-ae08-7f0e65fnfy02",
                    "updateTime": "1970-01-01T00:00:00Z",
                },
                "serviceName": "apikeys.googleapis.com",
                "status": {},
            },
            "receiveTimestamp": "2024-01-25 13:28:18.961519813",
            "resource": {
                "labels": {
                    "method": "google.api.apikeys.v2.ApiKeys.CreateKey",
                    "project_id": "some-project",
                    "service": "apikeys.googleapis.com",
                },
                "type": "audited_resource",
            },
            "severity": "NOTICE",
            "timestamp": "2024-01-25 13:28:18.961519813",
        },
    ),
    PantherRuleTest(
        Name="Log Without authorizationInfo",
        ExpectedResult=False,
        Log={
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "operation": {
                "id": "operations/akmf.p7-1028347275902-fe0c0688-44a7-4dca-bc06-8456068e5673",
                "last": True,
                "producer": "apikeys.googleapis.com",
            },
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "some.user@some-project.com",
                    "principalSubject": "serviceAccount:some-team@some-project.com",
                    "serviceAccountKeyName": "//iam.googleapis.com/projects/some-project/serviceAccounts/some-team@some-project.gserviceaccount.com/keys/dc5344c246064589v76ec76f66bafc92b093ed41",
                },
                "methodName": "google.api.apikeys.v2.ApiKeys.CreateKey",
                "request": {
                    "@type": "type.googleapis.com/google.api.apikeys.v2.CreateKeyRequest",
                    "parent": "projects/some-project/locations/global",
                },
                "requestMetadata": {
                    "callerIP": "189.163.74.177",
                    "callerSuppliedUserAgent": "(gzip),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {},
                },
                "resourceName": "projects/1028347245602",
                "response": {
                    "@type": "type.googleapis.com/google.api.apikeys.v2.Key",
                    "createTime": "1970-01-01T00:00:00Z",
                    "etag": 'W/"DSLGu9UKHwqq2ICm7YPE7g=="',
                    "name": "projects/1028347245602/locations/global/keys/bf67db25-d748-4335-ae08-7f0e65fnfy02",
                    "updateTime": "1970-01-01T00:00:00Z",
                },
                "serviceName": "apikeys.googleapis.com",
                "status": {},
            },
            "receiveTimestamp": "2024-01-25 13:28:18.961519813",
            "resource": {},
            "severity": "NOTICE",
            "timestamp": "2024-01-25 13:28:18.961519813",
        },
    ),
]


class GCPserviceusageapiKeyscreatePrivilegeEscalation(PantherRule):
    LogTypes = [LogType.GCP_AuditLog]
    Description = "Detects serviceusage.apiKeys.create method for privilege escalation in GCP. By default, API Keys are created with no restrictions, which means they have access to the entire GCP project they were created in. We can capitalize on that fact by creating a new API key that may have more privileges than our own user."
    DisplayName = "GCP serviceusage.apiKeys.create Privilege Escalation"
    RuleID = "GCP.serviceusage.apiKeys.create.Privilege.Escalation-prototype"
    Reference = "https://rhinosecuritylabs.com/cloud-security/privilege-escalation-google-cloud-platform-part-2/"
    Runbook = "Confirm this was authorized and necessary behavior. This is not a vulnerability in GCP, it is a vulnerability in how GCP environment is configured, so it is necessary to be aware of these attack vectors and to defend against them. It’s also important to remember that privilege escalation does not necessarily need to pass through the IAM service to be effective. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."
    Reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    Severity = PantherSeverity.High
    Tests = gc_pserviceusageapi_keyscreate_privilege_escalation_tests

    def rule(self, event):
        if not deep_get(event, "protoPayload", "methodName", default="METHOD_NOT_FOUND").endswith(
            "ApiKeys.CreateKey"
        ):
            return False
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if (
                auth.get("permission") == "serviceusage.apiKeys.create"
                and auth.get("granted") is True
            ):
                return True
        return False

    def title(self, event):
        actor = deep_get(
            event,
            "protoPayload",
            "authenticationInfo",
            "principalEmail",
            default="<ACTOR_NOT_FOUND>",
        )
        project_id = deep_get(
            event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
        )
        return f"[GCP]: [{actor}] created new API Key in project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
