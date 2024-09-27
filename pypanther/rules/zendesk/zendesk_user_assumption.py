from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class ZendeskUserAssumption(Rule):
    id = "Zendesk.UserAssumption-prototype"
    display_name = "Enabled Zendesk Support to Assume Users"
    log_types = [LogType.ZENDESK_AUDIT]
    tags = ["Zendesk", "Lateral Movement:Use Alternate Authentication Material"]
    reports = {"MITRE ATT&CK": ["TA0008:T1550"]}
    default_severity = Severity.MEDIUM
    default_description = "User enabled or disabled zendesk support user assumption."
    default_runbook = (
        "Investigate whether allowing zendesk support to assume users is necessary. If not, disable the feature.\n"
    )
    default_reference = "https://support.zendesk.com/hc/en-us/articles/4408894200474-Assuming-end-users#:~:text=In%20Support%2C%20click%20the%20Customers,user%20in%20the%20information%20dialog"
    summary_attributes = ["p_any_ip_addresses"]
    USER_SUSPENSION_ACTIONS = {"create", "update"}

    def rule(self, event):
        return (
            event.get("source_type") == "account_setting"
            and event.get("action", "") in self.USER_SUSPENSION_ACTIONS
            and (event.get("source_label", "").lower() in {"account assumption", "assumption duration"})
        )

    def title(self, event):
        return f"A user [{event.udm('actor_user')}] updated zendesk support user assumption settings"

    tests = [
        RuleTest(
            name="User assumption settings changed",
            expected_result=True,
            log={
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
        RuleTest(
            name="Zendesk - Credit Card Redaction On",
            expected_result=False,
            log={
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
