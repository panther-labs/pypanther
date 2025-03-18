from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPProjectExternalUserOwnershipInvite(Rule):
    display_name = "GCP External User Ownership Invite"
    id = "GCP.Project.ExternalUserOwnershipInvite-prototype"
    default_severity = Severity.HIGH
    log_types = [LogType.GCP_AUDIT_LOG]
    default_description = "This rule detects when an external user is invited as an owner of a GCP project using the InsertProjectOwnershipInvite event.\n"
    default_runbook = "Investigate the invitation to ensure it was authorized. Unauthorized invitations can lead to security risks. If the invitation was unauthorized, revoke the user's access to the project.\n"
    default_reference = "https://cloud.google.com/resource-manager/docs/project-ownership"

    def rule(self, event):
        if event.deep_get("protoPayload", "response", "error"):
            return False
        method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
        if method != "InsertProjectOwnershipInvite":
            return False
        authenticated = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="")
        expected_domain = authenticated.split("@")[-1]
        if event.deep_get("protoPayload", "request", "member", default="MEMBER_NOT_FOUND").endswith(
            f"@{expected_domain}",
        ):
            return False
        return True

    def title(self, event):
        member = event.deep_get("protoPayload", "request", "member", default="<MEMBER_NOT_FOUND>")
        project = event.deep_get("protoPayload", "resourceName", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: External user [{member}] was invited as owner to project [{project}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="External User Ownership Invite",
            expected_result=True,
            log={
                "insertId": "1abcd23efg456",
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "methodName": "InsertProjectOwnershipInvite",
                    "resourceName": "projects/target-project",
                    "authenticationInfo": {"principalEmail": "user@runpanther.com"},
                    "request": {
                        "member": "user:attacker@gmail.com",
                        "projectId": "target-project",
                        "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteRequest",
                    },
                    "response": {
                        "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteResponse",
                    },
                    "serviceName": "cloudresourcemanager.googleapis.com",
                },
                "resource": {"labels": {"project_id": "target-project"}, "type": "gce_project"},
                "severity": "NOTICE",
                "timestamp": "2023-10-01T12:34:56.789Z",
            },
        ),
        RuleTest(
            name="Internal User Ownership Invite",
            expected_result=False,
            log={
                "insertId": "2hijk34lmn789",
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "methodName": "InsertProjectOwnershipInvite",
                    "resourceName": "projects/target-project",
                    "authenticationInfo": {"principalEmail": "user@runpanther.com"},
                    "request": {
                        "member": "user:internal-user@runpanther.com",
                        "projectId": "target-project",
                        "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteRequest",
                    },
                    "response": {
                        "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteResponse",
                    },
                    "serviceName": "cloudresourcemanager.googleapis.com",
                },
                "resource": {"labels": {"project_id": "target-project"}, "type": "gce_project"},
                "severity": "NOTICE",
                "timestamp": "2023-10-01T12:45:56.789Z",
            },
        ),
    ]
