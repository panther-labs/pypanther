from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zendesk import ZENDESK_CHANGE_DESCRIPTION


@panther_managed
class ZendeskMobileAppAccessUpdated(Rule):
    id = "Zendesk.MobileAppAccessUpdated-prototype"
    display_name = "Zendesk Mobile App Access Modified"
    log_types = [LogType.ZENDESK_AUDIT]
    tags = ["Zendesk", "Persistence:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0003:T1078"]}
    default_severity = Severity.MEDIUM
    default_description = "A user updated account setting that enabled or disabled mobile app access."
    default_reference = "https://support.zendesk.com/hc/en-us/articles/4408846407066-About-the-Zendesk-Support-mobile-app#:~:text=More%20settings.-,Configuring%20the%20mobile%20app,-Activate%20the%20new"
    summary_attributes = ["p_any_ip_addresses"]
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

    tests = [
        RuleTest(
            name="Zendesk - Mobile App Access Off",
            expected_result=True,
            log={
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
        RuleTest(
            name="Zendesk - Mobile App Access On",
            expected_result=True,
            log={
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
        RuleTest(
            name="Zendesk - Credit Card Redaction",
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
