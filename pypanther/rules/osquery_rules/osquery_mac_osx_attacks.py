from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

osquery_mac_osx_attacks_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Valid malware discovered",
        ExpectedResult=True,
        Log={
            "name": "pack_osx-attacks_Leverage-A_1",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "path": "/Users/johnny/Desktop/Siri.app/Contents/MacOS/Siri",
                "pid": 100,
                "name": "Siri",
            },
        },
    ),
    PantherRuleTest(
        Name="Keyboard event taps query is ignored",
        ExpectedResult=False,
        Log={
            "name": "pack_osx-attacks_Keyboard_Event_Taps",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "path": "/System/Library/CoreServices/Siri.app/Contents/MacOS/Siri",
                "pid": 100,
                "name": "Siri",
            },
        },
    ),
]


class OsqueryMacOSXAttacks(PantherRule):
    RuleID = "Osquery.Mac.OSXAttacks-prototype"
    DisplayName = "macOS Malware Detected with osquery"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "MacOS", "Malware", "Resource Development:Develop Capabilities"]
    Reports = {"MITRE ATT&CK": ["TA0042:T1588"]}
    Severity = PantherSeverity.Medium
    Description = "Malware has potentially been detected on a macOS system"
    Runbook = "Check the executable against VirusTotal"
    Reference = "https://github.com/osquery/osquery/blob/master/packs/osx-attacks.conf"
    SummaryAttributes = ["name", "hostIdentifier", "action"]
    Tests = osquery_mac_osx_attacks_tests

    def rule(self, event):
        if "osx-attacks" not in event.get("name", ""):
            return False
        # There is another rule specifically for this query
        if "Keyboard_Event_Taps" in event.get("name", ""):
            return False
        if event.get("action") != "added":
            return False
        return True

    def title(self, event):
        return f"MacOS malware detected on [{event.get('hostIdentifier')}]"
