from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

zendesk_user_assumption_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User assumption settings changed",
        ExpectedResult=True,
        Log={
            "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
            "id": 123456789123,
            "action_label": "Updated",
            "actor_id": 123,
            "actor_name": "John Doe",
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
    PantherRuleTest(
        Name="Zendesk - Credit Card Redaction On",
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


class ZendeskUserAssumption(PantherRule):
    RuleID = "Zendesk.UserAssumption-prototype"
    DisplayName = "Enabled Zendesk Support to Assume Users"
    LogTypes = [LogType.Zendesk_Audit]
    Tags = ["Zendesk", "Lateral Movement:Use Alternate Authentication Material"]
    Reports = {"MITRE ATT&CK": ["TA0008:T1550"]}
    Severity = PantherSeverity.Medium
    Description = "User enabled or disabled zendesk support user assumption."
    Runbook = "Investigate whether allowing zendesk support to assume users is necessary. If not, disable the feature.\n"
    Reference = "https://support.zendesk.com/hc/en-us/articles/4408894200474-Assuming-end-users#:~:text=In%20Support%2C%20click%20the%20Customers,user%20in%20the%20information%20dialog"
    SummaryAttributes = ["p_any_ip_addresses"]
    Tests = zendesk_user_assumption_tests
    USER_SUSPENSION_ACTIONS = {"create", "update"}

    def rule(self, event):
        return (
            event.get("source_type") == "account_setting"
            and event.get("action", "") in self.USER_SUSPENSION_ACTIONS
            and (
                event.get("source_label", "").lower()
                in {"account assumption", "assumption duration"}
            )
        )

    def title(self, event):
        return (
            f"A user [{event.udm('actor_user')}] updated zendesk support user assumption settings"
        )
