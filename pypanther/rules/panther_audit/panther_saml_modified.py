from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

panther_saml_modified_tests: list[RuleTest] = [
    RuleTest(
        name="SAML config modified",
        expected_result=True,
        log={
            "actionName": "UPDATE_SAML_SETTINGS",
            "actionParams": {},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "111111"},
                "id": "111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
        },
    ),
    RuleTest(
        name="SAML config viewed",
        expected_result=False,
        log={
            "actionName": "GET_SAML_SETTINGS",
            "actionParams": {},
            "actionResult": "SUCCEEDED",
            "actor": {
                "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "111111"},
                "id": "111111",
                "name": "Homer Simpson",
                "type": "USER",
            },
            "errors": None,
            "p_log_type": "Panther.Audit",
        },
    ),
]


@panther_managed
class PantherSAMLModified(Rule):
    id = "Panther.SAML.Modified-prototype"
    display_name = "Panther SAML configuration has been modified"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.HIGH
    tags = ["DataModel", "Defense Evasion:Impair Defenses"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    default_description = "An Admin has modified Panther's SAML configuration."
    default_runbook = "Ensure this change was approved and appropriate."
    default_reference = "https://docs.panther.com/system-configuration/saml"
    summary_attributes = ["p_any_ip_addresses", "p_any_usernames"]
    tests = panther_saml_modified_tests

    def rule(self, event):
        return event.get("actionName") == "UPDATE_SAML_SETTINGS" and event.get("actionResult") == "SUCCEEDED"

    def title(self, event):
        return f"Panther SAML config has been modified by {event.udm('actor_user')}"

    def alert_context(self, event):
        return {"user": event.udm("actor_user"), "ip": event.udm("source_ip")}
