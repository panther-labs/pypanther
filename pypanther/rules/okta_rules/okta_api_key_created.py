from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get, okta_alert_context

okta_api_key_created_tests: list[RuleTest] = [
    RuleTest(
        name="API Key Created",
        expected_result=True,
        log={
            "uuid": "2a992f80-d1ad-4f62-900e-8c68bb72a21b",
            "published": "2021-01-08 21:28:34.875",
            "eventType": "system.api_token.create",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "api.token.create",
            "displayMessage": "Create API token",
            "actor": {
                "alternateId": "user@example.com",
                "displayName": "Test User",
                "id": "00u3q14ei6KUOm4Xi2p4",
                "type": "User",
            },
            "outcome": {"result": "SUCCESS"},
            "request": {},
            "debugContext": {},
            "target": [
                {
                    "id": "00Tpki36zlWjhjQ1u2p4",
                    "type": "Token",
                    "alternateId": "unknown",
                    "displayName": "test_key",
                    "details": None,
                },
            ],
        },
    ),
]


@panther_managed
class OktaAPIKeyCreated(Rule):
    id = "Okta.APIKeyCreated-prototype"
    display_name = "Okta API Key Created"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    tags = ["Identity & Access Management", "Okta", "Credential Access:Steal Application Access Token"]
    reports = {"MITRE ATT&CK": ["TA0006:T1528"]}
    default_severity = Severity.INFO
    default_description = "A user created an API Key in Okta"
    default_reference = "https://help.okta.com/en/prod/Content/Topics/Security/API.htm"
    default_runbook = "Reach out to the user if needed to validate the activity."
    summary_attributes = ["eventType", "severity", "displayMessage", "p_any_ip_addresses"]
    tests = okta_api_key_created_tests

    def rule(self, event):
        return (
            event.get("eventType", None) == "system.api_token.create"
            and deep_get(event, "outcome", "result") == "SUCCESS"
        )

    def title(self, event):
        target = event.get("target", [{}])
        key_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else "MISSING TARGET"
        return f"{deep_get(event, 'actor', 'displayName')} <{deep_get(event, 'actor', 'alternateId')}>created a new API key - <{key_name}>"

    def alert_context(self, event):
        return okta_alert_context(event)
