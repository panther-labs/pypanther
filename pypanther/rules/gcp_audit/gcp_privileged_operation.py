from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPPrivilegedOperation(Rule):
    id = "GCP.Privileged.Operation-prototype"
    default_description = "Detects privileged operations in GCP that could be part of a privilege escalation attempt, especially when following tag binding creation.\n"
    display_name = "GCP Privileged Operation"
    log_types = [LogType.GCP_AUDIT_LOG]
    create_alert = False
    default_runbook = "Check if the user has legitimate business need for this privileged operation. If unauthorized, revoke any recently created tag bindings and review IAM policies.\n"
    default_severity = Severity.INFO
    tags = ["attack.privilege_escalation", "attack.t1548", "gcp", "iam", "tagbinding"]
    PRIVILEGED_OPERATIONS = [
        "iam.serviceAccounts.getAccessToken",
        "orgpolicy.policy.set",
        "storage.hmacKeys.create",
        "serviceusage.apiKeys.create",
        "serviceusage.apiKeys.list",
    ]

    def rule(self, event):
        method_name = event.deep_get("protoPayload", "methodName", default="")
        return (
            method_name.endswith("setIamPolicy")
            or method_name.endswith("setIamPermissions")
            or method_name in self.PRIVILEGED_OPERATIONS
        )

    def title(self, event):
        principal = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN>")
        method = event.deep_get("protoPayload", "methodName", default="<UNKNOWN>")
        return f"GCP Privileged Operation by {principal} - {method}"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="Privileged Operation",
            expected_result=True,
            log={
                "protoPayload": {
                    "methodName": "compute.instances.setIamPolicy",
                    "authenticationInfo": {"principalEmail": "test@example.com"},
                    "resourceName": "projects/test-project",
                },
                "resource": {"labels": {"project_id": "test-project"}},
                "timestamp": "2024-01-01T00:00:00Z",
            },
        ),
        RuleTest(
            name="Normal Operation",
            expected_result=False,
            log={
                "protoPayload": {
                    "methodName": "compute.instances.list",
                    "authenticationInfo": {"principalEmail": "test@example.com"},
                    "resourceName": "projects/test-project",
                },
                "resource": {"labels": {"project_id": "test-project"}},
                "timestamp": "2024-01-01T00:00:00Z",
            },
        ),
    ]
