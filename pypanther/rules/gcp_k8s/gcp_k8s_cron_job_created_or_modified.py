from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPGKEKubernetesCronJobCreatedOrModified(Rule):
    id = "GCP.GKE.Kubernetes.Cron.Job.Created.Or.Modified-prototype"
    display_name = "GCP GKE Kubernetes Cron Job Created Or Modified"
    default_description = "This detection monitor for any modifications or creations of a cron job in GKE. Attackers may create or modify an existing scheduled job in order to achieve cluster persistence."
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.MEDIUM
    default_reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    default_runbook = "Investigate a reason of creating or modifying a cron job in GKE. Create ticket if appropriate."
    reports = {"MITRE ATT&CK": ["TA0003:T1053.003"]}

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if (
                auth.get("permission") in ["io.k8s.batch.v1.cronjobs.create", "io.k8s.batch.v1.cronjobs.update"]
                and auth.get("granted") is True
            ):
                return True
        return False

    def title(self, event):
        actor = event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)

    tests = [
        RuleTest(
            name="create",
            expected_result=True,
            log={
                "protoPayload": {
                    "authorizationInfo": [{"granted": True, "permission": "io.k8s.batch.v1.cronjobs.create"}],
                    "methodName": "v2.deploymentmanager.deployments.insert",
                    "serviceName": "deploymentmanager.googleapis.com",
                },
                "receiveTimestamp": "2024-01-19 13:47:19.465856238",
                "resource": {
                    "labels": {"name": "test-vm-deployment", "project_id": "panther-threat-research"},
                    "type": "deployment",
                },
                "severity": "NOTICE",
                "timestamp": "2024-01-19 13:47:18.279921000",
            },
        ),
        RuleTest(
            name="update",
            expected_result=True,
            log={
                "protoPayload": {
                    "authorizationInfo": [{"granted": True, "permission": "io.k8s.batch.v1.cronjobs.update"}],
                    "methodName": "v2.deploymentmanager.deployments.insert",
                    "serviceName": "deploymentmanager.googleapis.com",
                },
                "receiveTimestamp": "2024-01-19 13:47:19.465856238",
                "resource": {
                    "labels": {"name": "test-vm-deployment", "project_id": "panther-threat-research"},
                    "type": "deployment",
                },
                "severity": "NOTICE",
                "timestamp": "2024-01-19 13:47:18.279921000",
            },
        ),
        RuleTest(
            name="fail",
            expected_result=False,
            log={
                "protoPayload": {
                    "authorizationInfo": [{"granted": False, "permission": "cloudfunctions.functions.upsert"}],
                    "methodName": "v2.deploymentmanager.deployments.insert",
                    "serviceName": "deploymentmanager.googleapis.com",
                },
                "receiveTimestamp": "2024-01-19 13:47:19.465856238",
                "resource": {
                    "labels": {"name": "test-vm-deployment", "project_id": "panther-threat-research"},
                    "type": "deployment",
                },
                "severity": "NOTICE",
                "timestamp": "2024-01-19 13:47:18.279921000",
            },
        ),
    ]
