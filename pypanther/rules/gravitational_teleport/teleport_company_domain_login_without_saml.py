import re

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class TeleportCompanyDomainLoginWithoutSAML(Rule):
    id = "Teleport.CompanyDomainLoginWithoutSAML-prototype"
    display_name = "A User from the company domain(s) Logged in without SAML"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.HIGH
    default_description = "A User from the company domain(s) Logged in without SAML"
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "A User from the company domain(s) Logged in without SAML\n"
    summary_attributes = ["event", "code", "user", "method", "mfa_device"]
    TELEPORT_ORGANIZATION_DOMAINS_REGEX = "@(" + "|".join(config.TELEPORT_ORGANIZATION_DOMAINS) + ")$"

    def rule(self, event):
        return bool(
            event.get("event") == "user.login"
            and event.get("success") is True
            and bool(re.search(self.TELEPORT_ORGANIZATION_DOMAINS_REGEX, event.get("user")))
            and (event.get("method") != "saml"),
        )

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into [{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] without using SAML"

    tests = [
        RuleTest(
            name="A User from the company domain(s) logged in with SAML",
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
            name="A User from the company domain(s) logged in without SAML",
            expected_result=True,
            log={
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
