from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsquerySSHListener(Rule):
    id = "Osquery.SSHListener-prototype"
    display_name = "OSQuery Detected SSH Listener"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "Lateral Movement:Remote Services"]
    reports = {"MITRE ATT&CK": ["TA0008:T1021"]}
    default_severity = Severity.MEDIUM
    default_description = "Check if SSH is listening in a non-production environment. This could be an indicator of persistent access within an environment.\n"
    default_runbook = "Terminate the SSH daemon, investigate for signs of compromise.\n"
    default_reference = "https://medium.com/uptycs/osquery-what-it-is-how-it-works-and-how-to-use-it-ce4e81e60dfc"
    summary_attributes = ["action", "hostIdentifier", "name"]

    def rule(self, event):
        return (
            event.get("name") == "pack_incident-response_listening_ports"
            and event.deep_get("columns", "port") == "22"
            and (event.get("action") == "added")
        )

    tests = [
        RuleTest(
            name="SSH Listener Detected",
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
                "name": "pack_incident-response_listening_ports",
                "unixTime": "1536682461",
            },
        ),
        RuleTest(
            name="SSH Listener Not Detected",
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
