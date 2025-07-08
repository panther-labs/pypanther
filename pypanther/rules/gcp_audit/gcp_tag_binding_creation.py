from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPTagBindingCreation(Rule):
    id = "GCP.Tag.Binding.Creation-prototype"
    default_description = "Detects the creation of tag bindings in GCP, which could be part of a privilege escalation attempt using tag-based access control.\n"
    display_name = "GCP Tag Binding Creation"
    log_types = [LogType.GCP_AUDIT_LOG]
    create_alert = False
    default_runbook = "Verify if the user has legitimate business need for creating this tag binding. If unauthorized, revoke the tag binding and review IAM policies.\n"
    default_severity = Severity.INFO
    tags = ["attack.privilege_escalation", "attack.t1548", "gcp", "iam", "tagbinding"]

    def rule(self, event):
        method_name = event.deep_get("protoPayload", "methodName", default="")
        return method_name.endswith("TagBindings.CreateTagBinding")

    def title(self, event):
        principal = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN>")
        resource = event.deep_get("protoPayload", "resourceName", default="<UNKNOWN>")
        return f"GCP Tag Binding Creation by {principal} - {resource}"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="Tag Binding Creation",
            expected_result=True,
            log={
                "protoPayload": {
                    "methodName": "TagBindings.CreateTagBinding",
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
