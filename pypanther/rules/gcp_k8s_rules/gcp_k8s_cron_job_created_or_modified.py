from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk
from pypanther.log_types import LogType

gcpgke_kubernetes_cron_job_created_or_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="create",
        ExpectedResult=True,
        Log={
            "protoPayload": {
                "authorizationInfo": [
                    {"granted": True, "permission": "io.k8s.batch.v1.cronjobs.create"}
                ],
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
    PantherRuleTest(
        Name="update",
        ExpectedResult=True,
        Log={
            "protoPayload": {
                "authorizationInfo": [
                    {"granted": True, "permission": "io.k8s.batch.v1.cronjobs.update"}
                ],
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
    PantherRuleTest(
        Name="fail",
        ExpectedResult=False,
        Log={
            "protoPayload": {
                "authorizationInfo": [
                    {"granted": False, "permission": "cloudfunctions.functions.upsert"}
                ],
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


class GCPGKEKubernetesCronJobCreatedOrModified(PantherRule):
    RuleID = "GCP.GKE.Kubernetes.Cron.Job.Created.Or.Modified-prototype"
    DisplayName = "GCP GKE Kubernetes Cron Job Created Or Modified"
    Description = "This detection monitor for any modifications or creations of a cron job in GKE. Attackers may create or modify an existing scheduled job in order to achieve cluster persistence."
    LogTypes = [LogType.GCP_AuditLog]
    Severity = PantherSeverity.Medium
    Reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    Runbook = "Investigate a reason of creating or modifying a cron job in GKE. Create ticket if appropriate."
    Reports = {"MITRE ATT&CK": ["T1053.003"]}
    Tests = gcpgke_kubernetes_cron_job_created_or_modified_tests

    def rule(self, event):
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if (
                auth.get("permission")
                in ["io.k8s.batch.v1.cronjobs.create", "io.k8s.batch.v1.cronjobs.update"]
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
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(
            event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>"
        )
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
