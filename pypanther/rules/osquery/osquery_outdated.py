from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsqueryOutdatedAgent(Rule):
    id = "Osquery.OutdatedAgent-prototype"
    display_name = "Osquery Agent Outdated"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "Compliance"]
    default_severity = Severity.INFO
    default_description = "Keep track of osquery versions, current is 5.10.2."
    default_runbook = "Update the osquery agent."
    default_reference = "https://www.osquery.io/downloads/official/5.10.2"
    summary_attributes = ["name", "hostIdentifier", "action"]
    LATEST_VERSION = "5.10.2"

    def rule(self, event):
        return (
            event.get("name") == "pack_it-compliance_osquery_info"
            and event.deep_get("columns", "version") != self.LATEST_VERSION
            and (event.get("action") == "added")
        )

    def title(self, event):
        return f"Osquery Version {event.deep_get('columns', 'version')} is Outdated"

    tests = [
        RuleTest(
            name="osquery out of date",
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
        RuleTest(
            name="osquery up to date",
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
