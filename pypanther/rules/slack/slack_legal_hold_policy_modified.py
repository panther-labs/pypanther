from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.slack import slack_alert_context


@panther_managed
class SlackAuditLogsLegalHoldPolicyModified(Rule):
    id = "Slack.AuditLogs.LegalHoldPolicyModified-prototype"
    display_name = "Slack Legal Hold Policy Modified"
    log_types = [LogType.SLACK_AUDIT_LOGS]
    tags = ["Slack", "Defense Evasion", "Impair Defenses", "Disable or Modify Tools"]
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    default_severity = Severity.HIGH
    default_description = "Detects changes to configured legal hold policies"
    default_reference = "https://slack.com/intl/en-gb/help/articles/4401830811795-Create-and-manage-legal-holds"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    LEGAL_HOLD_POLICY_ACTIONS = {
        "legal_hold_policy_entities_deleted": "Slack Legal Hold Policy Entities Deleted",
        "legal_hold_policy_exclusion_added": "Slack Exclusions Added to Legal Hold Policy",
        "legal_hold_policy_released": "Slack Legal Hold Released",
        "legal_hold_policy_updated": "Slack Legal Hold Updated",
    }

    def rule(self, event):
        return event.get("action") in self.LEGAL_HOLD_POLICY_ACTIONS

    def title(self, event):
        # Only the `legal_hold_policy_updated` event includes relevant data to deduplicate
        if event.get("action") == "legal_hold_policy_updated":
            return f"Slack Legal Hold Updated [{event.deep_get('details', 'old_legal_hold_policy', 'name')}]"
        if event.get("action") in self.LEGAL_HOLD_POLICY_ACTIONS:
            return self.LEGAL_HOLD_POLICY_ACTIONS.get(event.get("action"))
        return "Slack Legal Hold Policy Modified"

    def alert_context(self, event):
        return slack_alert_context(event)

    tests = [
        RuleTest(
            name="Legal Hold - Entities Deleted",
            expected_result=True,
            log={
                "action": "legal_hold_policy_entities_deleted",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace",
                        "id": "T01234N56GB",
                        "name": "test-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
            },
        ),
        RuleTest(
            name="Legal Hold - Exclusions Added",
            expected_result=True,
            log={
                "action": "legal_hold_policy_exclusion_added",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace",
                        "id": "T01234N56GB",
                        "name": "test-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
            },
        ),
        RuleTest(
            name="Legal Hold - Policy Released",
            expected_result=True,
            log={
                "action": "legal_hold_policy_released",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace",
                        "id": "T01234N56GB",
                        "name": "test-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
            },
        ),
        RuleTest(
            name="Legal Hold - Policy Updated",
            expected_result=True,
            log={
                "action": "legal_hold_policy_updated",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "A012B3CDEFG",
                        "name": "username",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace",
                        "id": "T01234N56GB",
                        "name": "test-workspace",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
            },
        ),
        RuleTest(
            name="User Logout",
            expected_result=False,
            log={
                "action": "user_logout",
                "actor": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
                "context": {
                    "ip_address": "1.2.3.4",
                    "location": {
                        "domain": "test-workspace-1",
                        "id": "T01234N56GB",
                        "name": "test-workspace-1",
                        "type": "workspace",
                    },
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                },
                "date_create": "2022-07-28 15:22:32",
                "entity": {
                    "type": "user",
                    "user": {
                        "email": "user@example.com",
                        "id": "W012J3FEWAU",
                        "name": "primary-owner",
                        "team": "T01234N56GB",
                    },
                },
                "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
            },
        ),
    ]
