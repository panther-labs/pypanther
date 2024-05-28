from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

osquery_unsupported_mac_os_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="MacOS out of date",
        ExpectedResult=True,
        Log={
            "action": "added",
            "calendarTime": "Tue Sep 11 16:14:21 2018 UTC",
            "columns": {
                "build_distro": "10.14.2",
                "build_platform": "darwin",
                "config_hash": "1111",
                "config_valid": "1",
                "counter": "14",
                "global_state": "0",
                "extensions": "active",
                "instance_id": "1111",
                "pid": "223",
                "platform": "darwin",
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
            "name": "pack_vuln-management_os_version",
            "unixTime": "1536682461",
        },
    ),
    PantherRuleTest(
        Name="MacOS up to date",
        ExpectedResult=False,
        Log={
            "action": "added",
            "calendarTime": "Tue Sep 11 16:14:21 2018 UTC",
            "columns": {
                "build_distro": "10.15.1",
                "build_platform": "darwin",
                "config_hash": "1111",
                "config_valid": "1",
                "counter": "14",
                "global_state": "2",
                "extensions": "active",
                "instance_id": "1111",
                "pid": "223",
                "platform": "darwin",
                "resident_size": "54894592",
                "start_time": "1536634519",
                "system_time": "12472",
                "user_time": "31800",
                "uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
                "version": "10.15.2",
                "watcher": "92",
            },
            "counter": "255",
            "decorations": {"host_uuid": "1111", "environment": "corp"},
            "epoch": "0",
            "hostIdentifier": "test.lan",
            "log_type": "result",
            "name": "pack_vuln-management_os_version",
            "unixTime": "1536682461",
        },
    ),
]


class OsqueryUnsupportedMacOS(PantherRule):
    RuleID = "Osquery.UnsupportedMacOS-prototype"
    DisplayName = "Unsupported macOS version"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "Compliance"]
    Severity = PantherSeverity.Low
    Description = "Check that all laptops on the corporate environment are on a version of MacOS supported by IT.\n"
    Runbook = "Update the MacOs version"
    Reference = "https://support.apple.com/en-eg/HT201260"
    SummaryAttributes = ["name", "hostIdentifier", "action"]
    Tests = osquery_unsupported_mac_os_tests
    SUPPORTED_VERSIONS = ["10.15.1", "10.15.2", "10.15.3"]

    def rule(self, event):
        return (
            event.get("name") == "pack_vuln-management_os_version"
            and deep_get(event, "columns", "platform") == "darwin"
            and (deep_get(event, "columns", "version") not in self.SUPPORTED_VERSIONS)
            and (event.get("action") == "added")
        )
