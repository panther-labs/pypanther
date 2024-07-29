from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_config import config

g_suite_external_mail_forwarding_tests: list[RuleTest] = [
    RuleTest(
        name="Forwarding to External Address",
        expected_result=True,
        log={
            "id": {"applicationName": "user_accounts", "customerId": "D12345"},
            "actor": {"email": "homer.simpson@.springfield.io"},
            "type": "email_forwarding_change",
            "name": "email_forwarding_out_of_domain",
            "parameters": {"email_forwarding_destination_address": "HSimpson@gmail.com"},
        },
    ),
    RuleTest(
        name="Forwarding to External Address - Allowed Domain",
        expected_result=False,
        log={
            "id": {"applicationName": "user_accounts", "customerId": "D12345"},
            "actor": {"email": "homer.simpson@.springfield.io"},
            "type": "email_forwarding_change",
            "name": "email_forwarding_out_of_domain",
            "parameters": {"email_forwarding_destination_address": "HSimpson@example.com"},
        },
    ),
    RuleTest(
        name="Non Forwarding Event",
        expected_result=False,
        log={
            "id": {"applicationName": "user_accounts", "customerId": "D12345"},
            "actor": {"email": "homer.simpson@.springfield.io"},
            "type": "2sv_change",
            "name": "2sv_enroll",
        },
    ),
    RuleTest(
        name="ListObject Type",
        expected_result=False,
        log={
            "actor": {"email": "user@example.io", "profileId": "118111111111111111111"},
            "id": {
                "applicationName": "drive",
                "customerId": "D12345",
                "time": "2022-12-20 17:27:47.080000000",
                "uniqueQualifier": "-7312729053723258069",
            },
            "ipAddress": "12.12.12.12",
            "kind": "admin#reports#activity",
            "name": "rename",
            "parameters": {
                "actor_is_collaborator_account": None,
                "billable": True,
                "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
                "doc_title": "Document Title- Found Here",
                "doc_type": "presentation",
                "is_encrypted": None,
                "new_value": ["Document Title- Found Here"],
                "old_value": ["Document Title- Old"],
                "owner": "user@example.io",
                "owner_is_shared_drive": None,
                "owner_is_team_drive": None,
                "primary_event": True,
                "visibility": "private",
            },
            "type": "access",
        },
    ),
]


@panther_managed
class GSuiteExternalMailForwarding(Rule):
    id = "GSuite.ExternalMailForwarding-prototype"
    display_name = "Gsuite Mail forwarded to external domain"
    enabled = False
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    tags = ["GSuite", "Collection:Email Collection", "Configuration Required"]
    reports = {"MITRE ATT&CK": ["TA0009:T1114"]}
    default_severity = Severity.HIGH
    default_description = "A user has configured mail forwarding to an external domain\n"
    default_reference = "https://support.google.com/mail/answer/10957?hl=en&sjid=864417124752637253-EU"
    default_runbook = "Follow up with user to remove this forwarding rule if not allowed.\n"
    summary_attributes = ["p_any_emails"]
    tests = g_suite_external_mail_forwarding_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "user_accounts":
            return False
        if event.get("name") == "email_forwarding_out_of_domain":
            domain = deep_get(event, "parameters", "email_forwarding_destination_address").split("@")[-1]
            if domain not in config.GSUITE_TRUSTED_FORWARDING_DESTINATION_DOMAINS:
                return True
        return False

    def title(self, event):
        external_address = deep_get(event, "parameters", "email_forwarding_destination_address")
        user = deep_get(event, "actor", "email")
        return f"An email forwarding rule was created by {user} to {external_address}"
