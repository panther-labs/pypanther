from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.gcp_base_helpers import gcp_alert_context
from pypanther.helpers.panther_base_helpers import deep_get, deep_walk
from pypanther.log_types import LogType

gc_piamrolesupdate_privilege_escalation_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Test-876cde",
        ExpectedResult=False,
        Log={
            "p_enrichment": None,
            "protoPayload": {
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.roles.dunno",
                        "resource": "projects/some-research/roles/CustomRole",
                        "resourceAttributes": {},
                    }
                ]
            },
        },
    ),
    PantherRuleTest(
        Name="Test-ffdf6",
        ExpectedResult=True,
        Log={
            "p_enrichment": None,
            "protoPayload": {
                "authorizationInfo": [
                    {
                        "granted": True,
                        "permission": "iam.roles.update",
                        "resource": "projects/some-research/roles/CustomRole",
                        "resourceAttributes": {},
                    }
                ]
            },
        },
    ),
]


class GCPiamrolesupdatePrivilegeEscalation(PantherRule):
    RuleID = "GCP.iam.roles.update.Privilege.Escalation-prototype"
    DisplayName = "GCP iam.roles.update Privilege Escalation"
    Description = "If your user is assigned a custom IAM role, then iam.roles.update will allow you to update the “includedPermissons” on that role. Because it is assigned to you, you will gain the additional privileges, which could be anything you desire."
    LogTypes = [LogType.GCP_AuditLog]
    Tags = ["GCP"]
    Severity = PantherSeverity.High
    Reports = {"TA0004": ["T1548"]}
    Reference = (
        "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    )
    Runbook = "Confirm this was authorized and necessary behavior. This is not a vulnerability in GCP, it is a vulnerability in how GCP environment is configured, so it is necessary to be aware of these attack vectors and to defend against them. It’s also important to remember that privilege escalation does not necessarily need to pass through the IAM service to be effective. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."
    Tests = gc_piamrolesupdate_privilege_escalation_tests

    def rule(self, event):
        authorization_info = deep_walk(event, "protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "iam.roles.update" and auth.get("granted") is True:
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
