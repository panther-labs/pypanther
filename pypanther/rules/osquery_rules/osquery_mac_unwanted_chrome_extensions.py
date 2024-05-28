from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

osquery_mac_unwanted_chrome_extensions_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Unwanted Extension Detected",
        ExpectedResult=True,
        Log={
            "action": "added",
            "calendarTime": "Tue Sep 11 16:14:21 2018 UTC",
            "columns": {
                "build_distro": "10.12",
                "build_platform": "darwin",
                "config_hash": "1111",
                "config_valid": "1",
                "counter": "14",
                "global_state": "0",
                "extensions": "active",
                "instance_id": "1111",
                "pid": "223",
                "port": "22",
                "resident_size": "54894592",
                "start_time": "1536634519",
                "system_time": "12472",
                "user_time": "31800",
                "uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
                "version": "Not Supported",
                "watcher": "92",
            },
            "counter": "255",
            "decorations": {"host_uuid": "1111", "environment": "corp"},
            "epoch": "0",
            "hostIdentifier": "test.lan",
            "log_type": "result",
            "name": "pack_unwanted-chrome-extensions_pup1",
            "unixTime": "1536682461",
        },
    ),
    PantherRuleTest(
        Name="No Unwanted Chrome Extension Detected",
        ExpectedResult=False,
        Log={
            "action": "added",
            "calendarTime": "Tue Sep 11 16:14:21 2018 UTC",
            "columns": {
                "build_distro": "10.12",
                "build_platform": "darwin",
                "config_hash": "1111",
                "config_valid": "1",
                "counter": "14",
                "global_state": "2",
                "extensions": "active",
                "instance_id": "1111",
                "pid": "223",
                "port": "443",
                "resident_size": "54894592",
                "start_time": "1536634519",
                "system_time": "12472",
                "user_time": "31800",
                "uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
                "version": "10.14.2",
                "watcher": "92",
            },
            "counter": "255",
            "decorations": {"host_uuid": "1111", "environment": "corp"},
            "epoch": "0",
            "hostIdentifier": "test.lan",
            "log_type": "result",
            "name": "pack_incident-response_listening_ports",
            "unixTime": "1536682461",
        },
    ),
]


class OsqueryMacUnwantedChromeExtensions(PantherRule):
    RuleID = "Osquery.Mac.UnwantedChromeExtensions-prototype"
    DisplayName = "OSQuery Detected Unwanted Chrome Extensions"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "MacOS", "Malware", "Persistence:Browser Extensions"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1176"]}
    Severity = PantherSeverity.Medium
    Description = "Monitor for chrome extensions that could lead to a credential compromise.\n"
    Runbook = "Uninstall the unwanted extension"
    Reference = "https://securelist.com/threat-in-your-browser-extensions/107181/"
    SummaryAttributes = ["action", "hostIdentifier", "name"]
    Tests = osquery_mac_unwanted_chrome_extensions_tests

    def rule(self, event):
        return "unwanted-chrome-extensions" in event.get("name") and event.get("action") == "added"

    def title(self, event):
        return f"Unwanted Chrome extension(s) detected on [{event.get('hostIdentifier')}]"
