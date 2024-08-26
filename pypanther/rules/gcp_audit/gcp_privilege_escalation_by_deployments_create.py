from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk

gcp_privilege_escalation_by_deployments_create_tests: list[RuleTest] = [
    RuleTest(
        name="privilege-escalation",
        expected_result=True,
        log={
            "protoPayload": {
                "authorizationInfo": [{"granted": True, "permission": "deploymentmanager.deployments.create"}],
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
                "authorizationInfo": [{"granted": "афдиу", "permission": "deploymentmanager.deployments.create"}],
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


@panther_managed
class GCPPrivilegeEscalationByDeploymentsCreate(Rule):
    id = "GCP.Privilege.Escalation.By.Deployments.Create-prototype"
    display_name = "GCP.Privilege.Escalation.By.Deployments.Create"
    default_description = (
        "Detects privilege escalation in GCP by taking over the deploymentsmanager.deployments.create permission"
    )
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.HIGH
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    default_runbook = "Confirm this was authorized and necessary behavior. This is not a vulnerability in GCP, it is a vulnerability in how GCP environment is configured, so it is necessary to be aware of these attack vectors and to defend against them. It’s also important to remember that privilege escalation does not necessarily need to pass through the IAM service to be effective. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    tests = gcp_privilege_escalation_by_deployments_create_tests

    def rule(self, event):
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "deploymentmanager.deployments.create" and auth.get("granted") is True:
                return True
        return False

    def title(self, event):
        actor = deep_get(event, "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>")
        operation = deep_get(event, "protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
        project_id = deep_get(event, "resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")
        return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"

    def alert_context(self, event):
        return gcp_alert_context(event)
