from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

osquery_mac_application_firewall_settings_tests: list[RuleTest] = [
    RuleTest(
        name="ALF Disabled",
        expected_result=True,
        log={
            "name": "pack_incident-response_alf",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "logging_enabled": "0",
                "stealth_enabled": "0",
                "firewall_unload": "0",
                "allow_signed_enabled": "0",
                "global_state": "0",
                "logging_option": "0",
                "version": "1.6",
            },
        },
    ),
    RuleTest(
        name="ALF Enabled",
        expected_result=False,
        log={
            "name": "pack_incident-response_alf",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "logging_enabled": "1",
                "stealth_enabled": "1",
                "firewall_unload": "0",
                "allow_signed_enabled": "1",
                "global_state": "1",
                "logging_option": "0",
                "version": "1.6",
            },
        },
    ),
]


@panther_managed
class OsqueryMacApplicationFirewallSettings(Rule):
    id = "Osquery.Mac.ApplicationFirewallSettings-prototype"
    display_name = "MacOS ALF is misconfigured"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "MacOS", "Security Control", "Defense Evasion:Impair Defenses"]
    reports = {"CIS": ["2.6.3", "2.6.4"], "MITRE ATT&CK": ["TA0005:T1562"]}
    default_severity = Severity.HIGH
    default_description = "The application level firewall blocks unwanted network connections made to your computer from other computers on your network.\n"
    default_runbook = "Re-enable the firewall manually or with configuration management"
    default_reference = "https://support.apple.com/en-us/HT201642"
    summary_attributes = ["name", "hostIdentifier", "action"]
    tests = osquery_mac_application_firewall_settings_tests
    QUERIES = {"pack_incident-response_alf", "pack/mac-cis/ApplicationFirewall"}

    def rule(self, event):
        if event.get("name") not in self.QUERIES:
            return False
        if event.get("action") != "added":
            return False
        # 0 If the firewall is disabled
        # 1 If the firewall is enabled with exceptions
        # 2 If the firewall is configured to block all incoming connections
        # Stealth mode is a best practice to avoid responding to unsolicited probes
        return (
            int(deep_get(event, "columns", "global_state")) == 0
            or int(deep_get(event, "columns", "stealth_enabled")) == 0
        )

    def title(self, event):
        return f"MacOS firewall disabled on [{event.get('hostIdentifier')}]"
