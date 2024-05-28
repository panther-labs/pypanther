from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION
from pypanther.log_types import LogType

zendesk_sensitive_data_redaction_off_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Zendesk - Credit Card Redaction Off",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "account_setting",
            "source_label": "Credit Card Redaction",
            "action": "create",
            "change_description": "Disabled",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Credit Card Redaction On",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "account_setting",
            "source_label": "Credit Card Redaction",
            "action": "create",
            "change_description": "Enabled",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
    PantherRuleTest(
        Name="User assumption settings changed",
        ExpectedResult=False,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "source_id": 123,
            "source_type": "account_setting",
            "source_label": "Account Assumption",
            "action": "update",
            "change_description": "Changed",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
]


class ZendeskSensitiveDataRedactionOff(PantherRule):
    RuleID = "Zendesk.SensitiveDataRedactionOff-prototype"
    DisplayName = "Zendesk Credit Card Redaction Off"
    LogTypes = [LogType.Zendesk_Audit]
    Tags = ["Zendesk", "Collection:Data from Information Repositories"]
    Reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    Severity = PantherSeverity.High
    Description = "A user updated account setting that disabled credit card redaction."
    Runbook = "Re-enable credit card redaction."
    Reference = "https://support.zendesk.com/hc/en-us/articles/4408822124314-Automatically-redacting-credit-card-numbers-from-tickets"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = zendesk_sensitive_data_redaction_off_tests
    REDACTION_ACTIONS = {"create", "destroy"}

    def rule(self, event):
        return (
            event.get("source_type") == "account_setting"
            and event.get("action", "") in self.REDACTION_ACTIONS
            and (event.get("source_label", "") == "Credit Card Redaction")
        )

    def title(self, event):
        action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
        return f"User [{event.udm('actor_user')}] {action} credit card redaction"

    def severity(self, event):
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() != "disabled":
            return "INFO"
        return "HIGH"
