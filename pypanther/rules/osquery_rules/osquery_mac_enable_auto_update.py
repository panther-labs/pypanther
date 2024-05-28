from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

osquery_mac_auto_update_enabled_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Auto Updates Disabled",
        ExpectedResult=True,
        Log={
            "columns": {
                "domain": "com.apple.SoftwareUpdate",
                "key": "AutomaticCheckEnabled",
                "value": "false",
            },
            "action": "added",
            "name": "pack/mac-cis/SoftwareUpdate",
        },
    ),
    PantherRuleTest(
        Name="Auto Updates Enabled",
        ExpectedResult=False,
        Log={
            "columns": {
                "domain": "com.apple.SoftwareUpdate",
                "key": "AutomaticCheckEnabled",
                "value": "true",
            },
            "action": "added",
            "name": "pack/mac-cis/SoftwareUpdate",
        },
    ),
    PantherRuleTest(
        Name="Wrong Key",
        ExpectedResult=False,
        Log={
            "columns": {
                "domain": "com.apple.SoftwareUpdate",
                "key": "LastFullSuccessfulDate",
                "value": "false",
            },
            "action": "added",
            "name": "pack/mac-cis/SoftwareUpdate",
        },
    ),
]


class OsqueryMacAutoUpdateEnabled(PantherRule):
    RuleID = "Osquery.Mac.AutoUpdateEnabled-prototype"
    DisplayName = "OSQuery Reports Application Firewall Disabled"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "MacOS", "Security Control", "Defense Evasion:Impair Defenses"]
    Reports = {"CIS": ["1.2"], "MITRE ATT&CK": ["TA0005:T1562"]}
    Severity = PantherSeverity.Medium
    DedupPeriodMinutes = 1440
    Description = "Verifies that MacOS has automatic software updates enabled.\n"
    Runbook = "Enable the auto updates on the host.\n"
    Reference = "https://support.apple.com/en-gb/guide/mac-help/mchlpx1065/mac"
    SummaryAttributes = ["name", "action", "p_any_ip_addresses", "p_any_domain_names"]
    Tests = osquery_mac_auto_update_enabled_tests

    def rule(self, event):
        # Send an alert if not set to "true"
        return (
            "SoftwareUpdate" in event.get("name", [])
            and event.get("action") == "added"
            and (deep_get(event, "columns", "domain") == "com.apple.SoftwareUpdate")
            and (deep_get(event, "columns", "key") == "AutomaticCheckEnabled")
            and (deep_get(event, "columns", "value") == "false")
        )
