from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPK8sNewDaemonsetDeployed(Rule):
    id = "GCP.K8s.New.Daemonset.Deployed-prototype"
    display_name = "GCP K8s New Daemonset Deployed"
    default_description = "Detects Daemonset creation in GCP Kubernetes clusters."
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.MEDIUM
    default_reference = "https://medium.com/snowflake/from-logs-to-detection-using-snowflake-and-panther-to-detect-k8s-threats-d72f70a504d7"
    default_runbook = "Investigate a reason of creating Daemonset. Create ticket if appropriate."
    reports = {"MITRE ATT&CK": ["TA0002:T1610"]}

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "io.k8s.apps.v1.daemonsets.create" and auth.get("granted") is True:
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
            name="privilege-escalation",
            expected_result=True,
            log={
                "protoPayload": {
                    "authorizationInfo": [{"granted": True, "permission": "io.k8s.apps.v1.daemonsets.create"}],
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
                    "authorizationInfo": [{"granted": False, "permission": "io.k8s.apps.v1.daemonsets.create"}],
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
