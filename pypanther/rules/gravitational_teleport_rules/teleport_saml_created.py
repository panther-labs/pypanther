from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

teleport_saml_created_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="SAML Auth Connector modified",
        ExpectedResult=True,
        Log={
            "cluster_name": "teleport.example.com",
            "code": "T8200I",
            "ei": 0,
            "event": "saml.created",
            "name": "okta",
            "time": "2023-09-19 18:00:00",
            "uid": "88888888-4444-4444-4444-222222222222",
            "user": "max.mustermann@zumbeispiel.example",
        },
    )
]


class TeleportSAMLCreated(PantherRule):
    RuleID = "Teleport.SAMLCreated-prototype"
    DisplayName = "A SAML Connector was created or modified"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["Teleport"]
    Severity = PantherSeverity.High
    Description = "A SAML connector was created or modified"
    Reports = {"MITRE ATT&CK": ["TA0042:T1585"]}
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "When a SAML connector is modified, it can potentially change the trust model of the Teleport Cluster. Validate that these changes were expected and correct.\n"
    SummaryAttributes = ["event", "code", "user", "name"]
    Tests = teleport_saml_created_tests

    def rule(self, event):
        return event.get("event") == "saml.created"

    def title(self, event):
        return f"A SAML connector was created or updated by User [{event.get('user', '<UNKNOWN_USER>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
