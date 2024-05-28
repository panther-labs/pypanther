from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.log_types import LogType

teleport_root_login_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="User logged in as root",
        ExpectedResult=True,
        Log={
            "addr_remote": "192.0.2.1:35194",
            "cluster_name": "teleport.example.com",
            "code": "t2000i",
            "ei": 0,
            "event": "session.start",
            "initial_command": [""],
            "login": "root",
            "namespace": "default",
            "proto": "ssh",
            "server_hostname": "ip-10-0-0-1.us-west-2.compute.internal",
            "server_id": "12345678-1111-2222-3333-54e9467ff0e6",
            "server_labels": {"env": "prod", "role": "project123"},
            "session_recording": "node-sync",
            "sid": "12345678-1111-2222-3333-54e9467ff0e6",
            "size": "80:25",
            "time": "2023-09-18 11:22:33",
            "uid": "12345678-1111-2222-3333-54e9467ff0e6",
            "user": "max.mustermann@zumbeispiel.example",
        },
    )
]


class TeleportRootLogin(PantherRule):
    RuleID = "Teleport.RootLogin-prototype"
    DisplayName = "User Logged in as root"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["SSH", "Execution:Command and Scripting Interpreter", "Teleport"]
    Severity = PantherSeverity.Medium
    Description = "A User logged in as root"
    Reports = {"MITRE ATT&CK": ["TA0002:T1059"]}
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "Use user accounts and policies, rather than root when logging in. With access to root, it is possible to evade auditing and logging.\n"
    SummaryAttributes = ["event", "code", "user", "login", "server_hostname", "server_labels"]
    Tests = teleport_root_login_tests

    def rule(self, event):
        return event.get("event") == "session.start" and event.get("login") == "root"

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into [{event.get('server_hostname', '<UNKNOWN_HOSTNAME>')}] as root on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
