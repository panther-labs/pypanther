from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPiamserviceAccountKeyscreate(Rule):
    id = "GCP.iam.serviceAccountKeys.create-prototype"
    display_name = "GCP.Iam.ServiceAccountKeys.Create"
    default_description = "If your user is assigned a custom IAM role, then iam.roles.update will allow you to update the “includedPermissons” on that role. Because it is assigned to you, you will gain the additional privileges, which could be anything you desire."
    log_types = [LogType.GCP_AUDIT_LOG]
    default_severity = Severity.HIGH
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    default_runbook = "Confirm this was authorized and necessary behavior. This is not a vulnerability in GCP, it is a vulnerability in how GCP environment is configured, so it is necessary to be aware of these attack vectors and to defend against them. It’s also important to remember that privilege escalation does not necessarily need to pass through the IAM service to be effective. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."
    reports = {"MITRE ATT&CK": ["TA0004:T1548"]}

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "iam.serviceAccountKeys.create" and auth.get("granted") is True:
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
                    "authorizationInfo": [{"granted": True, "permission": "iam.serviceAccountKeys.create"}],
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
                    "authorizationInfo": [{"granted": False, "permission": "iam.serviceAccountKeys.create"}],
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
