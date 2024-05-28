from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION
from pypanther.log_types import LogType

zendesk_mobile_app_access_updated_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Zendesk - Mobile App Access Off",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "account_setting",
            "source_label": "Zendesk Support Mobile App Access",
            "action": "create",
            "change_description": "Disabled",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Mobile App Access On",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
            "source_id": 123,
            "source_type": "account_setting",
            "source_label": "Zendesk Support Mobile App Access",
            "action": "create",
            "change_description": "Enabled",
            "ip_address": "127.0.0.1",
            "created_at": "2021-05-28T18:39:50Z",
            "p_log_type": "Zendesk.Audit",
        },
    ),
    PantherRuleTest(
        Name="Zendesk - Credit Card Redaction",
        ExpectedResult=False,
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
]


class ZendeskMobileAppAccessUpdated(PantherRule):
    RuleID = "Zendesk.MobileAppAccessUpdated-prototype"
    DisplayName = "Zendesk Mobile App Access Modified"
    LogTypes = [LogType.Zendesk_Audit]
    Tags = ["Zendesk", "Persistence:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1078"]}
    Severity = PantherSeverity.Medium
    Description = "A user updated account setting that enabled or disabled mobile app access."
    Reference = "https://support.zendesk.com/hc/en-us/articles/4408846407066-About-the-Zendesk-Support-mobile-app#:~:text=More%20settings.-,Configuring%20the%20mobile%20app,-Activate%20the%20new"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = zendesk_mobile_app_access_updated_tests
    MOBILE_APP_ACTIONS = {"create", "update"}

    def rule(self, event):
        return (
            event.get("source_type") == "account_setting"
            and event.get("action", "") in self.MOBILE_APP_ACTIONS
            and (event.get("source_label", "") == "Zendesk Support Mobile App Access")
        )

    def title(self, event):
        action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
        return f"User [{event.udm('actor_user')}] {action} mobile app access"

    def severity(self, event):
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
            return "INFO"
        return "MEDIUM"
