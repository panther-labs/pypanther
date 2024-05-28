from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk
from pypanther.log_types import LogType

gc_piamservice_account_keyscreate_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="privilege-escalation",
        ExpectedResult=True,
        Log={
            "protoPayload": {
                "authorizationInfo": [
                    {"granted": True, "permission": "iam.serviceAccountKeys.create"}
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
                    {"granted": False, "permission": "iam.serviceAccountKeys.create"}
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


class GCPiamserviceAccountKeyscreate(PantherRule):
    RuleID = "GCP.iam.serviceAccountKeys.create-prototype"
    DisplayName = "GCP.Iam.ServiceAccountKeys.Create"
    Description = "If your user is assigned a custom IAM role, then iam.roles.update will allow you to update the “includedPermissons” on that role. Because it is assigned to you, you will gain the additional privileges, which could be anything you desire."
    LogTypes = [LogType.GCP_AuditLog]
    Severity = PantherSeverity.High
    Reference = (
        "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    )
    Runbook = "Confirm this was authorized and necessary behavior. This is not a vulnerability in GCP, it is a vulnerability in how GCP environment is configured, so it is necessary to be aware of these attack vectors and to defend against them. It’s also important to remember that privilege escalation does not necessarily need to pass through the IAM service to be effective. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."
    Reports = {"MITRE ATT&CK": ["TA0004:T1548"]}
    Tests = gc_piamservice_account_keyscreate_tests

    def rule(self, event):
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if (
                auth.get("permission") == "iam.serviceAccountKeys.create"
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
