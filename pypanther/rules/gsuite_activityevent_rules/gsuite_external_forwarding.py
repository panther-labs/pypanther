from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_config import config
from pypanther.log_types import LogType

g_suite_external_mail_forwarding_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Forwarding to External Address",
        ExpectedResult=True,
        Log={
            "id": {"applicationName": "user_accounts", "customerId": "D12345"},
            "actor": {"email": "homer.simpson@.springfield.io"},
            "type": "email_forwarding_change",
            "name": "email_forwarding_out_of_domain",
            "parameters": {"email_forwarding_destination_address": "HSimpson@gmail.com"},
        },
    ),
    PantherRuleTest(
        Name="Forwarding to External Address - Allowed Domain",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "user_accounts", "customerId": "D12345"},
            "actor": {"email": "homer.simpson@.springfield.io"},
            "type": "email_forwarding_change",
            "name": "email_forwarding_out_of_domain",
            "parameters": {"email_forwarding_destination_address": "HSimpson@example.com"},
        },
    ),
    PantherRuleTest(
        Name="Non Forwarding Event",
        ExpectedResult=False,
        Log={
            "id": {"applicationName": "user_accounts", "customerId": "D12345"},
            "actor": {"email": "homer.simpson@.springfield.io"},
            "type": "2sv_change",
            "name": "2sv_enroll",
        },
    ),
    PantherRuleTest(
        Name="ListObject Type",
        ExpectedResult=False,
        Log={
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


class GSuiteExternalMailForwarding(PantherRule):
    RuleID = "GSuite.ExternalMailForwarding-prototype"
    DisplayName = "Gsuite Mail forwarded to external domain"
    Enabled = False
    LogTypes = [LogType.GSuite_ActivityEvent]
    Tags = ["GSuite", "Collection:Email Collection", "Configuration Required"]
    Reports = {"MITRE ATT&CK": ["TA0009:T1114"]}
    Severity = PantherSeverity.High
    Description = "A user has configured mail forwarding to an external domain\n"
    Reference = "https://support.google.com/mail/answer/10957?hl=en&sjid=864417124752637253-EU"
    Runbook = "Follow up with user to remove this forwarding rule if not allowed.\n"
    SummaryAttributes = ["p_any_emails"]
    Tests = g_suite_external_mail_forwarding_tests

    def rule(self, event):
        if deep_get(event, "id", "applicationName") != "user_accounts":
            return False
        if event.get("name") == "email_forwarding_out_of_domain":
            domain = deep_get(event, "parameters", "email_forwarding_destination_address").split(
                "@"
            )[-1]
            if domain not in config.GSUITE_TRUSTED_FORWARDING_DESTINATION_DOMAINS:
                return True
        return False

    def title(self, event):
        external_address = deep_get(event, "parameters", "email_forwarding_destination_address")
        user = deep_get(event, "actor", "email")
        return f"An email forwarding rule was created by {user} to {external_address}"
