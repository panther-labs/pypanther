from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

one_password_sensitive_item_tests: list[RuleTest] = [
    RuleTest(
        name="1Password - Sensitive Item Accessed",
        expected_result=True,
        log={
            "uuid": "ecd1d435c26440dc930ddfbbef201a11",
            "timestamp": "2022-02-23 20:27:17.071",
            "used_version": 2,
            "vault_uuid": "111111",
            "item_uuid": "ecd1d435c26440dc930ddfbbef201a11",
            "user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "2222222"},
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20195",
                "ip_address": "1.1.1.1.1",
                "os_name": "MacOSX",
                "os_version": "10.15.7",
                "platform_name": "Chrome",
                "platform_version": "4.0.4.102",
            },
            "p_log_type": "OnePassword.ItemUsage",
        },
    ),
    RuleTest(
        name="1Password - Regular Item Usage",
        expected_result=False,
        log={
            "uuid": "11111",
            "timestamp": "2022-02-23 20:27:17.071",
            "used_version": 2,
            "vault_uuid": "111111",
            "item_uuid": "1111111",
            "user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "2222222"},
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20195",
                "ip_address": "1.1.1.1.1",
                "os_name": "MacOSX",
                "os_version": "10.15.7",
                "platform_name": "Chrome",
                "platform_version": "4.0.4.102",
            },
            "p_log_type": "OnePassword.ItemUsage",
        },
    ),
]


@panther_managed
class OnePasswordSensitiveItem(Rule):
    id = "OnePassword.Sensitive.Item-prototype"
    dedup_period_minutes = 30
    display_name = "Configuration Required - Sensitive 1Password Item Accessed"
    enabled = False
    log_types = [LogType.ONEPASSWORD_ITEM_USAGE]
    default_reference = "https://support.1password.com/1password-com-items/"
    default_severity = Severity.LOW
    default_description = "Alerts when a user defined list of sensitive items in 1Password is accessed"
    summary_attributes = ["p_any_ip_addresses", "p_any_emails"]
    tags = ["Configuration Required", "1Password", "Credential Access:Unsecured Credentials"]
    reports = {"MITRE ATT&CK": ["TA0006:T1552"]}
    tests = one_password_sensitive_item_tests
    "\nThis rule detects access to high sensitivity items in your 1Password account. 1Password references\nthese items by their UUID so the SENSITIVE_ITEM_WATCHLIST below allows for the mapping of UUID to\nmeaningful name.\n\nThere is an alternative method for creating this rule that uses Panther's lookup table feature,\n(currently in beta). That rule can be found in the 1Password detection pack with the name\nBETA - Sensitive 1Password Item Accessed (onepassword_lut_sensitive_item_access.py)\n"
    SENSITIVE_ITEM_WATCHLIST = {"ecd1d435c26440dc930ddfbbef201a11": "demo_item"}

    def rule(self, event):
        return event.get("item_uuid") in self.SENSITIVE_ITEM_WATCHLIST.keys()

    def title(self, event):
        return f"A Sensitive 1Password Item was Accessed by user {deep_get(event, 'user', 'name')}"

    def alert_context(self, event):
        context = {
            "user": deep_get(event, "user", "name"),
            "item_name": deep_get(event, "p_enrichment", "1Password Translation", "item_uuid", "title"),
            "client": deep_get(event, "client", "app_name"),
            "ip_address": event.udm("source_ip"),
            "event_time": event.get("timestamp"),
        }
        return context
