from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

osquery_unsupported_mac_os_tests: list[RuleTest] = [
    RuleTest(
        name="MacOS out of date",
        expected_result=True,
        log={
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
    RuleTest(
        name="MacOS up to date",
        expected_result=False,
        log={
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


@panther_managed
class OsqueryUnsupportedMacOS(Rule):
    id = "Osquery.UnsupportedMacOS-prototype"
    display_name = "Unsupported macOS version"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "Compliance"]
    default_severity = Severity.LOW
    default_description = (
        "Check that all laptops on the corporate environment are on a version of MacOS supported by IT.\n"
    )
    default_runbook = "Update the MacOs version"
    default_reference = "https://support.apple.com/en-eg/HT201260"
    summary_attributes = ["name", "hostIdentifier", "action"]
    tests = osquery_unsupported_mac_os_tests
    SUPPORTED_VERSIONS = ["10.15.1", "10.15.2", "10.15.3"]

    def rule(self, event):
        return (
            event.get("name") == "pack_vuln-management_os_version"
            and deep_get(event, "columns", "platform") == "darwin"
            and (deep_get(event, "columns", "version") not in self.SUPPORTED_VERSIONS)
            and (event.get("action") == "added")
        )
