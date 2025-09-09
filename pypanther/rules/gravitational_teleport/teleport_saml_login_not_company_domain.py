from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TeleportSAMLLoginWithoutCompanyDomain(Rule):
    id = "Teleport.SAMLLoginWithoutCompanyDomain-prototype"
    display_name = "A user authenticated with SAML, but from an unknown company domain"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.MEDIUM
    default_description = "A user authenticated with SAML, but from an unknown company domain"
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "A user authenticated with SAML, but from an unknown company domain\n"
    summary_attributes = ["event", "code", "user", "method", "mfa_device"]

    def rule(self, event):
        cluster = event.get("cluster_name", "")
        user_domain = event.get("user", "@").split("@")[-1]
        return (
            event.get("event") == "user.login"
            and event.get("success") is True
            and (event.get("method") == "saml")
            and (not cluster.endswith(user_domain))
        )

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into [{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] using SAML from a different domain"

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
