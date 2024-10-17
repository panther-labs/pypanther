from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.gcp import gcp_alert_context


@panther_managed
class GCPiamrolesupdatePrivilegeEscalation(Rule):
    id = "GCP.iam.roles.update.Privilege.Escalation-prototype"
    display_name = "GCP iam.roles.update Privilege Escalation"
    default_description = "If your user is assigned a custom IAM role, then iam.roles.update will allow you to update the “includedPermissons” on that role. Because it is assigned to you, you will gain the additional privileges, which could be anything you desire."
    log_types = [LogType.GCP_AUDIT_LOG]
    tags = ["GCP"]
    default_severity = Severity.HIGH
    reports = {"TA0004": ["T1548"]}
    default_reference = "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/"
    default_runbook = "Confirm this was authorized and necessary behavior. This is not a vulnerability in GCP, it is a vulnerability in how GCP environment is configured, so it is necessary to be aware of these attack vectors and to defend against them. It’s also important to remember that privilege escalation does not necessarily need to pass through the IAM service to be effective. Make sure to follow the principle of least-privilege in your environments to help mitigate these security risks."

    def rule(self, event):
        authorization_info = event.deep_walk("protoPayload", "authorizationInfo")
        if not authorization_info:
            return False
        for auth in authorization_info:
            if auth.get("permission") == "iam.roles.update" and auth.get("granted") is True:
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
            name="Test-876cde",
            expected_result=False,
            log={
                "p_enrichment": None,
                "protoPayload": {
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iam.roles.dunno",
                            "resource": "projects/some-research/roles/CustomRole",
                            "resourceAttributes": {},
                        },
                    ],
                },
            },
        ),
        RuleTest(
            name="Test-ffdf6",
            expected_result=True,
            log={
                "p_enrichment": None,
                "protoPayload": {
                    "authorizationInfo": [
                        {
                            "granted": True,
                            "permission": "iam.roles.update",
                            "resource": "projects/some-research/roles/CustomRole",
                            "resourceAttributes": {},
                        },
                    ],
                },
            },
        ),
    ]
