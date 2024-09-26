from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsqueryMacUnwantedChromeExtensions(Rule):
    id = "Osquery.Mac.UnwantedChromeExtensions-prototype"
    display_name = "OSQuery Detected Unwanted Chrome Extensions"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "MacOS", "Malware", "Persistence:Browser Extensions"]
    reports = {"MITRE ATT&CK": ["TA0003:T1176"]}
    default_severity = Severity.MEDIUM
    default_description = "Monitor for chrome extensions that could lead to a credential compromise.\n"
    default_runbook = "Uninstall the unwanted extension"
    default_reference = "https://securelist.com/threat-in-your-browser-extensions/107181/"
    summary_attributes = ["action", "hostIdentifier", "name"]

    def rule(self, event):
        return "unwanted-chrome-extensions" in event.get("name") and event.get("action") == "added"

    def title(self, event):
        return f"Unwanted Chrome extension(s) detected on [{event.get('hostIdentifier')}]"

    tests = [
        RuleTest(
            name="Unwanted Extension Detected",
            expected_result=True,
            log={
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
        RuleTest(
            name="No Unwanted Chrome Extension Detected",
            expected_result=False,
            log={
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
