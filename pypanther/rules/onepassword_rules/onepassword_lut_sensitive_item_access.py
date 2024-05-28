from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

one_password_lut_sensitive_item_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="1Password - Sensitive Item Accessed",
        ExpectedResult=True,
        Log={
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20195",
                "ip_address": "1.1.1.1",
                "os_name": "MacOSX",
                "os_version": "10.15.7",
                "platform_name": "Chrome",
                "platform_version": "98.0.4758.102",
            },
            "item_uuid": "1234",
            "p_enrichment": {
                "1Password Translation": {
                    "item_uuid": {
                        "title": "demo_item",
                        "updatedAt": "2022-02-14 17:44:50.000000000",
                        "uuid": "12344321",
                    }
                }
            },
            "p_log_type": "OnePassword.ItemUsage",
            "timestamp": "2022-02-23 22:11:50.591",
            "user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "12345"},
            "uuid": "12345",
            "vault_uuid": "54321",
        },
    ),
    PantherRuleTest(
        Name="1Password - Non-Sensitive Item Accessed",
        ExpectedResult=False,
        Log={
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20195",
                "ip_address": "1.1.1.1",
                "os_name": "MacOSX",
                "os_version": "10.15.7",
                "platform_name": "Chrome",
                "platform_version": "98.0.4758.102",
            },
            "item_uuid": "1234",
            "p_enrichment": {
                "1Password Translation": {
                    "item_uuid": {
                        "title": "not_sensitive",
                        "updatedAt": "2022-02-14 17:44:50.000000000",
                        "uuid": "12344321",
                    }
                }
            },
            "p_log_type": "OnePassword.ItemUsage",
            "timestamp": "2022-02-23 22:11:50.591",
            "user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "12345"},
            "uuid": "12345",
            "vault_uuid": "54321",
        },
    ),
]


class OnePasswordLutSensitiveItem(PantherRule):
    RuleID = "OnePassword.Lut.Sensitive.Item-prototype"
    DedupPeriodMinutes = 30
    DisplayName = "BETA - Sensitive 1Password Item Accessed"
    Enabled = False
    LogTypes = [LogType.OnePassword_ItemUsage]
    Reference = "https://support.1password.com/1password-com-items/"
    Severity = PantherSeverity.Low
    Description = "Alerts when a user defined list of sensitive items in 1Password is accessed"
    SummaryAttributes = ["p_any_ip_addresses", "p_any_emails"]
    Tags = [
        "Configuration Required",
        "1Password",
        "Lookup Table",
        "BETA",
        "Credential Access:Unsecured Credentials",
    ]
    Reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    Tests = one_password_lut_sensitive_item_tests
    "\nThis rule requires the use of the Lookup Table feature currently in Beta in Panther, 1Password\nlogs reference items by their UUID without human-friendly titles. The instructions to create a\nlookup table to do this translation can be found at :\n\n https://docs.runpanther.io/guides/using-lookup-tables-1password-uuids\n\nThe steps detailed in that document are required for this rule to function as intended.\n"
    # Add the human-readable names of 1Password items you want to monitor
    SENSITIVE_ITEM_WATCHLIST = ["demo_item"]

    def rule(self, event):
        return (
            deep_get(event, "p_enrichment", "1Password Translation", "item_uuid", "title")
            in self.SENSITIVE_ITEM_WATCHLIST
        )

    def title(self, event):
        return f"A Sensitive 1Password Item was Accessed by user {deep_get(event, 'user', 'name')}"

    def alert_context(self, event):
        context = {
            "user": deep_get(event, "user", "name"),
            "item_name": deep_get(
                event, "p_enrichment", "1Password Translation", "item_uuid", "title"
            ),
            "client": deep_get(event, "client", "app_name"),
            "ip_address": event.udm("source_ip"),
            "event_time": event.get("timestamp"),
        }
        return context
