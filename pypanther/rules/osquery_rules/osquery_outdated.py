from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

osquery_outdated_agent_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="osquery out of date",
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
                "resident_size": "54894592",
                "start_time": "1536634519",
                "system_time": "12472",
                "user_time": "31800",
                "uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
                "version": "3.1.2",
                "watcher": "92",
            },
            "counter": "255",
            "decorations": {"host_uuid": "1111", "environment": "corp"},
            "epoch": "0",
            "hostIdentifier": "test.lan",
            "log_type": "result",
            "name": "pack_it-compliance_osquery_info",
            "unixTime": "1536682461",
        },
    ),
    PantherRuleTest(
        Name="osquery up to date",
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
                "resident_size": "54894592",
                "start_time": "1536634519",
                "system_time": "12472",
                "user_time": "31800",
                "uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
                "version": "5.10.2",
                "watcher": "92",
            },
            "counter": "255",
            "decorations": {"host_uuid": "1111", "environment": "corp"},
            "epoch": "0",
            "hostIdentifier": "test.lan",
            "log_type": "result",
            "name": "pack_it-compliance_osquery_info",
            "unixTime": "1536682461",
        },
    ),
]


class OsqueryOutdatedAgent(PantherRule):
    RuleID = "Osquery.OutdatedAgent-prototype"
    DisplayName = "Osquery Agent Outdated"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "Compliance"]
    Severity = PantherSeverity.Info
    Description = "Keep track of osquery versions, current is 5.10.2."
    Runbook = "Update the osquery agent."
    Reference = "https://www.osquery.io/downloads/official/5.10.2"
    SummaryAttributes = ["name", "hostIdentifier", "action"]
    Tests = osquery_outdated_agent_tests
    LATEST_VERSION = "5.10.2"

    def rule(self, event):
        return (
            event.get("name") == "pack_it-compliance_osquery_info"
            and deep_get(event, "columns", "version") != self.LATEST_VERSION
            and (event.get("action") == "added")
        )

    def title(self, event):
        return f"Osquery Version {deep_get(event, 'columns', 'version')} is Outdated"
