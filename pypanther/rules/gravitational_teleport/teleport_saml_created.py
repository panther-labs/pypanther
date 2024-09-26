from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TeleportSAMLCreated(Rule):
    id = "Teleport.SAMLCreated-prototype"
    display_name = "A SAML Connector was created or modified"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.HIGH
    default_description = "A SAML connector was created or modified"
    reports = {"MITRE ATT&CK": ["TA0042:T1585"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "When a SAML connector is modified, it can potentially change the trust model of the Teleport Cluster. Validate that these changes were expected and correct.\n"
    summary_attributes = ["event", "code", "user", "name"]

    def rule(self, event):
        return event.get("event") == "saml.created"

    def title(self, event):
        return f"A SAML connector was created or updated by User [{event.get('user', '<UNKNOWN_USER>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"

    tests = [
        RuleTest(
            name="SAML Auth Connector modified",
            expected_result=True,
            log={
                "cluster_name": "teleport.example.com",
                "code": "T8200I",
                "ei": 0,
                "event": "saml.created",
                "name": "okta",
                "time": "2023-09-19 18:00:00",
                "uid": "88888888-4444-4444-4444-222222222222",
                "user": "max.mustermann@zumbeispiel.example",
            },
        ),
    ]
