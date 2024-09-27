import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class TeleportSAMLLoginWithoutCompanyDomain(Rule):
    id = "Teleport.SAMLLoginWithoutCompanyDomain-prototype"
    display_name = "A user authenticated with SAML, but from an unknown company domain"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.HIGH
    default_description = "A user authenticated with SAML, but from an unknown company domain"
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "A user authenticated with SAML, but from an unknown company domain\n"
    summary_attributes = ["event", "code", "user", "method", "mfa_device"]
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

    tests = [
        RuleTest(
            name="A user authenticated with SAML, but from a known company domain",
            expected_result=False,
            log={
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
        RuleTest(
            name="A user authenticated with SAML, but not from a company domain",
            expected_result=True,
            log={
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
