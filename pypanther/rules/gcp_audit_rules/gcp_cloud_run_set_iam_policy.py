from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk

gcp_cloud_run_set_iam_policy_tests: list[RuleTest] = [
    RuleTest(
        name="GCP Run IAM Policy Set",
        expected_result=True,
        log={
            "insertId": "l3jvzyd2s2s",
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "some.user@company.com",
                    "principalSubject": "user:some.user@company.com",
                },
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "run.services.setIamPolicy",
                        "resource": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                        "resourceAttributes": {},
                    },
                    {"granted": True, "permission": "run.services.setIamPolicy", "resourceAttributes": {}},
                ],
                "methodName": "google.cloud.run.v1.Services.SetIamPolicy",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {"bindings": [{"members": ["user:some.user@company.com"], "role": "roles/run.invoker"}]},
                    "resource": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                },
                "requestMetadata": {
                    "callerIP": "1.2.3.4",
                    "callerSuppliedUserAgent": "(gzip),gzip(gfe)",
                    "destinationAttributes": {},
                    "requestAttributes": {"auth": {}, "time": "2024-02-02T09:44:26.173186Z"},
                },
                "resourceLocation": {"currentLocations": ["us-west1"]},
                "resourceName": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                "response": {
                    "@type": "type.googleapis.com/google.iam.v1.Policy",
                    "bindings": [{"members": ["user:some.user@company.com"], "role": "roles/run.invoker"}],
                    "etag": "BwYQYvUoBxs=",
                },
                "serviceName": "run.googleapis.com",
            },
            "receiveTimestamp": "2024-02-02 09:44:26.653891982",
            "resource": {
                "labels": {
                    "configuration_name": "",
                    "location": "us-west1",
                    "project_id": "some-project",
                    "revision_name": "",
                    "service_name": "",
                },
                "type": "cloud_run_revision",
            },
            "severity": "NOTICE",
            "timestamp": "2024-02-02 09:44:26.029835000",
        },
    ),
    RuleTest(
        name="GCP Run IAM Policy Not Set",
        expected_result=False,
        log={
            "insertId": "l3jvzyd2s2s",
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "some.user@company.com",
                    "principalSubject": "user:some.user@company.com",
                },
                "authorizationInfo": [
                    {
                        "granted": False,
                        "permission": "run.services.setIamPolicy",
                        "resource": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                        "resourceAttributes": {},
                    },
                    {"granted": False, "permission": "run.services.setIamPolicy", "resourceAttributes": {}},
                ],
                "methodName": "google.cloud.run.v1.Services.SetIamPolicy",
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {"bindings": [{"members": ["user:some.user@company.com"], "role": "roles/run.invoker"}]},
                    "resource": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                },
                "requestMetadata": "...",
                "resourceLocation": "...",
                "resourceName": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                "serviceName": "run.googleapis.com",
            },
            "receiveTimestamp": "2024-02-02 09:44:26.653891982",
            "resource": "...",
            "severity": "NOTICE",
            "timestamp": "2024-02-02 09:44:26.029835000",
        },
    ),
    RuleTest(
        name="No method provided",
        expected_result=False,
        log={
            "insertId": "l3jvzyd2s2s",
            "logName": "projects/some-project/logs/cloudaudit.googleapis.com%2Factivity",
            "protoPayload": {
                "at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": "some.user@company.com",
                    "principalSubject": "user:some.user@company.com",
                },
                "authorizationInfo": [
                    {
                        "granted": False,
                        "permission": "run.services.setIamPolicy",
                        "resource": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                        "resourceAttributes": {},
                    },
                    {"granted": False, "permission": "run.services.setIamPolicy", "resourceAttributes": {}},
                ],
                "request": {
                    "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest",
                    "policy": {"bindings": [{"members": ["user:some.user@company.com"], "role": "roles/run.invoker"}]},
                    "resource": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                },
                "requestMetadata": "...",
                "resourceLocation": "...",
                "resourceName": "projects/some-project/locations/us-west1/services/cloudrun-exfil",
                "serviceName": "run.googleapis.com",
            },
            "receiveTimestamp": "2024-02-02 09:44:26.653891982",
            "resource": "...",
            "severity": "NOTICE",
            "timestamp": "2024-02-02 09:44:26.029835000",
        },
    ),
]


@panther_managed
class GCPCloudRunSetIAMPolicy(Rule):
    log_types = [LogType.GCP_AUDIT_LOG]
    default_description = "Detects new roles granted to users to Cloud Run Services. This could potentially allow the user to perform actions within the project and its resources, which could pose a security risk."
    display_name = "GCP Cloud Run Set IAM Policy"
    id = "GCP.Cloud.Run.Set.IAM.Policy-prototype"
    default_reference = "https://cloud.google.com/run/docs/securing/managing-access"
    default_runbook = "Confirm this was authorized and necessary behavior"
    default_severity = Severity.HIGH
    tests = gcp_cloud_run_set_iam_policy_tests

    def rule(self, event):
        if deep_get(event, "severity") == "ERROR":
            return False
        method_name = deep_get(event, "protoPayload", "methodName", default="")
        if not method_name.endswith("Services.SetIamPolicy"):
            return False
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "run.services.setIamPolicy" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        resource = deep_get(event, "resource", "resourceName", default="<RESOURCE_NOT_FOUND>")
        assigned_role = deep_walk(event, "protoPayload", "response", "bindings", "role")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] was granted access to [{resource}] service with the [{assigned_role}] role in project [{project_id}]"

    def alert_context(self, event):
        context = gcp_alert_context(event)
        context["assigned_role"] = deep_walk(event, "protoPayload", "response", "bindings", "role")
        return context
