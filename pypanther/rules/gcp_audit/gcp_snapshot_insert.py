from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPComputeSnapshotUnexpectedDomain(Rule):
    display_name = "GCP Snapshot Creation Detection"
    enabled = False
    id = "GCP.Compute.Snapshot.UnexpectedDomain-prototype"
    default_severity = Severity.MEDIUM
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["Configuration Required"]
    default_description = (
        "This rule detects when someone with an unexpected email domain creates a snapshot of a Compute Disk.\n"
    )
    default_runbook = "Investigate the snapshot creation to ensure it was authorized. Unauthorized snapshot creation can lead to data exfiltration.\n"
    default_reference = "https://cloud.google.com/compute/docs/disks/snapshots"
    EXPECTED_DOMAIN = "@your-domain.tld"

    def rule(self, event):
        if event.deep_get("protoPayload", "response", "error"):
            return False
        method = event.deep_get("protoPayload", "methodName", default="METHOD_NOT_FOUND")
        if method != "v1.compute.snapshots.insert":
            return False
        email = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="")
        if not email.endswith(self.EXPECTED_DOMAIN):
            return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        project = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: Unexpected domain [{actor}] created a snapshot on project [{project}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="Snapshot creation by user with unexpected domain",
            expected_result=True,
            log={
                "insertId": "1abcd23efg456",
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@unexpected-domain.com"},
                    "methodName": "v1.compute.snapshots.insert",
                    "resourceName": "projects/test-project/global/snapshots/snapshot-1",
                    "serviceName": "compute.googleapis.com",
                },
                "resource": {"labels": {"project_id": "test-project"}, "type": "gce_snapshot"},
                "severity": "NOTICE",
                "timestamp": "2023-10-01T12:34:56.789Z",
            },
        ),
        RuleTest(
            name="Snapshot creation by user with expected domain",
            expected_result=False,
            log={
                "insertId": "2hijk34lmn789",
                "logName": "projects/test-project/logs/cloudaudit.googleapis.com%2Factivity",
                "protoPayload": {
                    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "authenticationInfo": {"principalEmail": "user@your-domain.tld"},
                    "methodName": "v1.compute.snapshots.insert",
                    "resourceName": "projects/test-project/global/snapshots/snapshot-2",
                    "serviceName": "compute.googleapis.com",
                },
                "resource": {"labels": {"project_id": "test-project"}, "type": "gce_snapshot"},
                "severity": "NOTICE",
                "timestamp": "2023-10-01T12:45:56.789Z",
            },
        ),
    ]
