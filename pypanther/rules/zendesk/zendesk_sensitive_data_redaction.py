from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zendesk import ZENDESK_CHANGE_DESCRIPTION


@panther_managed
class ZendeskSensitiveDataRedactionOff(Rule):
    id = "Zendesk.SensitiveDataRedactionOff-prototype"
    display_name = "Zendesk Credit Card Redaction Off"
    log_types = [LogType.ZENDESK_AUDIT]
    tags = ["Zendesk", "Collection:Data from Information Repositories"]
    reports = {"MITRE ATT&CK": ["TA0009:T1213"]}
    default_severity = Severity.HIGH
    default_description = "A user updated account setting that disabled credit card redaction."
    default_runbook = "Re-enable credit card redaction."
    default_reference = "https://support.zendesk.com/hc/en-us/articles/4408822124314-Automatically-redacting-credit-card-numbers-from-tickets"
    summary_attributes = ["p_any_ip_addresses"]
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

    tests = [
        RuleTest(
            name="Zendesk - Credit Card Redaction Off",
            expected_result=True,
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
                "change_description": "Disabled",
                "ip_address": "127.0.0.1",
                "created_at": "2021-05-28T18:39:50Z",
                "p_log_type": "Zendesk.Audit",
            },
        ),
        RuleTest(
            name="Zendesk - Credit Card Redaction On",
            expected_result=True,
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
        RuleTest(
            name="User assumption settings changed",
            expected_result=False,
            log={
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
