from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

panther_saml_modified_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="SAML config modified",
        ExpectedResult=True,
        Log={
            "actionName": "UPDATE_SAML_SETTINGS",
            "actionParams": {},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {
                    "email": "homer@springfield.gov",
                    "emailVerified": True,
                    "roleId": "111111",
                },
                "id": "111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
        },
    ),
    PantherRuleTest(
        Name="SAML config viewed",
        ExpectedResult=False,
        Log={
            "actionName": "GET_SAML_SETTINGS",
            "actionParams": {},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {
                    "email": "homer@springfield.gov",
                    "emailVerified": True,
                    "roleId": "111111",
                },
                "id": "111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
        },
    ),
]


class PantherSAMLModified(PantherRule):
    RuleID = "Panther.SAML.Modified-prototype"
    DisplayName = "Panther SAML configuration has been modified"
    LogTypes = [LogType.Panther_Audit]
    Severity = PantherSeverity.High
    Tags = ["DataModel", "Defense Evasion:Impair Defenses"]
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Description = "An Admin has modified Panther's SAML configuration."
    Runbook = "Ensure this change was approved and appropriate."
    Reference = "https://docs.panther.com/system-configuration/saml"
    SummaryAttributes = ["p_any_ip_addresses", "p_any_usernames"]
    Tests = panther_saml_modified_tests

    def rule(self, event):
        return (
            event.get("actionName") == "UPDATE_SAML_SETTINGS"
            and event.get("actionResult") == "SUCCEEDED"
        )

    def title(self, event):
        return f"Panther SAML config has been modified by {event.udm('actor_user')}"

    def alert_context(self, event):
        return {"user": event.udm("actor_user"), "ip": event.udm("source_ip")}
