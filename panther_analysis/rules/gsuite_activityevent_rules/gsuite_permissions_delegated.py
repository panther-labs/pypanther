from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_base_helpers import deep_get

g_suite_permisssions_delegated_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Other Admin Action",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "admin"},
            "type": "DELEGATED_ADMIN_SETTINGS",
            "name": "RENAME_ROLE",
            "parameters": {"ROLE_NAME": "Vault Admins", "USER_EMAIL": "homer.simpson@example.com"},
        },
    ),
    PantherRuleTest(
        Name="Privileges Assigned",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "admin"},
            "type": "DELEGATED_ADMIN_SETTINGS",
            "name": "ASSIGN_ROLE",
            "parameters": {"ROLE_NAME": "Vault Admins", "USER_EMAIL": "homer.simpson@example.com"},
        },
    ),
]


class GSuitePermisssionsDelegated(PantherRule):
    RuleID = "GSuite.PermisssionsDelegated-prototype"
    DisplayName = "--DEPRECATED-- GSuite User Delegated Admin Permissions"
    Enabled = False
    LogTypes = ["GSuite.ActivityEvent"]
    Tags = ["GSuite", "Configuration Required", "Deprecated"]
    Severity = Severity.Low
    Description = "A GSuite user was granted new administrator privileges.\n"
    Reference = "https://support.google.com/a/answer/167094?hl=en&sjid=864417124752637253-EU"
    Runbook = "Valdiate that this users should have these permissions and they are not the result of a privilege escalation attack.\n"
    SummaryAttributes = ["actor:email"]
    Tests = g_suite_permisssions_delegated_tests
    PERMISSION_DELEGATED_EVENTS = {"ASSIGN_ROLE"}

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "admin":
            return False
        if event.get("type") == "DELEGATED_ADMIN_SETTINGS":
            return bool(event.get("name") in self.PERMISSION_DELEGATED_EVENTS)
        return False

    def title(self, event):
        role = deep_get(event, "parameters", "ROLE_NAME")
        user = deep_get(event, "parameters", "USER_EMAIL")
        if not role:
            role = "<UNKNOWN_ROLE>"
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] delegated new administrator privileges [{role}] to [{user}]"
