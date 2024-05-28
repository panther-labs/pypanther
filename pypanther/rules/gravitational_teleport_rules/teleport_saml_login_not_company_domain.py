import re
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_config import config
from pypanther.log_types import LogType

teleport_saml_login_without_company_domain_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="A user authenticated with SAML, but from a known company domain",
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
        Name="A user authenticated with SAML, but not from a company domain",
        ExpectedResult=True,
        Log={
            "cluster_name": "teleport.example.com",
            "code": "T1001I",
            "ei": 0,
            "event": "user.login",
            "method": "saml",
            "success": True,
            "time": "2023-09-18 00:00:00",
            "uid": "88888888-4444-4444-4444-222222222222",
            "user": "wtf.how@omghax.gravitational.io",
        },
    ),
]


class TeleportSAMLLoginWithoutCompanyDomain(PantherRule):
    RuleID = "Teleport.SAMLLoginWithoutCompanyDomain-prototype"
    DisplayName = "A user authenticated with SAML, but from an unknown company domain"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["Teleport"]
    Severity = PantherSeverity.High
    Description = "A user authenticated with SAML, but from an unknown company domain"
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "A user authenticated with SAML, but from an unknown company domain\n"
    SummaryAttributes = ["event", "code", "user", "method", "mfa_device"]
    Tests = teleport_saml_login_without_company_domain_tests
    TELEPORT_COMPANY_DOMAINS_REGEX = "@(" + "|".join(config.TELEPORT_ORGANIZATION_DOMAINS) + ")$"

    def rule(self, event):
        return (
            event.get("event") == "user.login"
            and event.get("success") is True
            and (event.get("method") == "saml")
            and (not re.search(self.TELEPORT_COMPANY_DOMAINS_REGEX, event.get("user")))
        )

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into [{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] using SAML, but not from a known company domain in ({','.join(config.TELEPORT_ORGANIZATION_DOMAINS)})"
