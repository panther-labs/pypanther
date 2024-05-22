import re
from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from panther_analysis.helpers.panther_config import config

teleport_company_domain_login_without_saml_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="A User from the company domain(s) logged in with SAML",
        ExpectedResult=False,
        Log={
            "attributes": {"firstName": [""], "groups": ["employees"]},
            "cluster_name": "teleport.example.com",
            "code": "T1001I",
            "ei": 0,
            "event": "user.login",
            "method": "saml",
            "success": True,
            "time": "2023-09-18 00:00:00",
            "uid": "88888888-4444-4444-4444-222222222222",
            "user": "jane.doe@example.com",
        },
    ),
    PantherRuleTest(
        Name="A User from the company domain(s) logged in without SAML",
        ExpectedResult=True,
        Log={
            "cluster_name": "teleport.example.com",
            "code": "T1001I",
            "ei": 0,
            "event": "user.login",
            "method": "local",
            "success": True,
            "time": "2023-09-18 00:00:00",
            "uid": "88888888-4444-4444-4444-222222222222",
            "user": "jane.doe@example.com",
        },
    ),
]


class TeleportCompanyDomainLoginWithoutSAML(PantherRule):
    RuleID = "Teleport.CompanyDomainLoginWithoutSAML-prototype"
    DisplayName = "A User from the company domain(s) Logged in without SAML"
    Enabled = True
    LogTypes = ["Gravitational.TeleportAudit"]
    Tags = ["Teleport"]
    Severity = Severity.High
    Description = "A User from the company domain(s) Logged in without SAML"
    DedupPeriodMinutes = 60
    Reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "A User from the company domain(s) Logged in without SAML\n"
    SummaryAttributes = ["event", "code", "user", "method", "mfa_device"]
    Tests = teleport_company_domain_login_without_saml_tests
    TELEPORT_ORGANIZATION_DOMAINS_REGEX = (
        "@(" + "|".join(config.TELEPORT_ORGANIZATION_DOMAINS) + ")$"
    )

    def rule(self, event):
        return bool(
            event.get("event") == "user.login"
            and event.get("success") is True
            and bool(re.search(self.TELEPORT_ORGANIZATION_DOMAINS_REGEX, event.get("user")))
            and (event.get("method") != "saml")
        )

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into [{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] without using SAML"
