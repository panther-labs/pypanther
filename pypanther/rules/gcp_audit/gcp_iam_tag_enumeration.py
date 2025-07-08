from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPIAMTagEnumeration(Rule):
    id = "GCP.IAM.Tag.Enumeration-prototype"
    default_description = "Detects enumeration of IAM policies and tags in GCP, which could be a precursor to privilege escalation attempts via tag-based access control.\n"
    display_name = "GCP IAM and Tag Enumeration"
    log_types = [LogType.GCP_AUDIT_LOG]
    create_alert = False
    default_runbook = "Review if the user has legitimate business need for these enumeration operations. If unauthorized, review and update IAM policies.\n"
    default_severity = Severity.INFO
    tags = ["attack.reconnaissance", "attack.t1548", "gcp", "iam", "tagbinding"]

    def rule(self, event):
        enum_iam_tags = [
            "GetIamPolicy",
            "TagKeys.ListTagKeys",
            "TagKeys.ListTagValues",
            "TagBindings.ListEffectiveTags",
        ]
        method_name = event.deep_get("protoPayload", "methodName", default="")
        return any(tag in method_name for tag in enum_iam_tags)

    def title(self, event):
        principal = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<UNKNOWN>")
        method = event.deep_get("protoPayload", "methodName", default="<UNKNOWN>")
        return f"GCP IAM and Tag Enumeration by {principal} - {method}"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="IAM Policy Enumeration",
            expected_result=True,
            log={
                "protoPayload": {
                    "methodName": "GetIamPolicy",
                    "authenticationInfo": {"principalEmail": "test@example.com"},
                    "resourceName": "projects/test-project",
                },
                "resource": {"labels": {"project_id": "test-project"}},
                "timestamp": "2024-01-01T00:00:00Z",
            },
        ),
        RuleTest(
            name="Tag Keys Enumeration",
            expected_result=True,
            log={
                "protoPayload": {
                    "methodName": "TagKeys.ListTagKeys",
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
