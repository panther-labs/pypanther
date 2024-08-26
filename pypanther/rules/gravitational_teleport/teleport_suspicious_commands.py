from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

teleport_suspicious_commands_tests: list[RuleTest] = [
    RuleTest(
        name="Echo command",
        expected_result=False,
        log={
            "argv": [],
            "cgroup_id": 4294967537,
            "code": "T4000I",
            "ei": 15,
            "event": "session.command",
            "login": "root",
            "namespace": "default",
            "path": "/bin/echo",
            "pid": 7143,
            "ppid": 7115,
            "program": "echo",
            "return_code": 0,
            "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
            "sid": "8a3fc038-785b-43f3-8737-827b3e25fe5b",
            "time": "2020-08-17T17:40:37.491Z",
            "uid": "8eaf8f39-09d4-4a42-a22a-65163d2af702",
            "user": "panther",
        },
    ),
    RuleTest(
        name="Netcat command",
        expected_result=True,
        log={
            "argv": ["-l", "-p", "11434"],
            "cgroup_id": 4294967537,
            "code": "T4000I",
            "ei": 15,
            "event": "session.command",
            "login": "root",
            "namespace": "default",
            "path": "/bin/nc",
            "pid": 7143,
            "ppid": 7115,
            "program": "nc",
            "return_code": 0,
            "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
            "sid": "8a3fc038-785b-43f3-8737-827b3e25fe5b",
            "time": "2020-08-17T17:40:37.491Z",
            "uid": "8eaf8f39-09d4-4a42-a22a-65163d2af702",
            "user": "panther",
        },
    ),
]


@panther_managed
class TeleportSuspiciousCommands(Rule):
    id = "Teleport.SuspiciousCommands-prototype"
    display_name = "Teleport Suspicious Commands Executed"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["SSH", "Execution:Command and Scripting Interpreter"]
    default_severity = Severity.MEDIUM
    default_description = "A user has invoked a suspicious command that could lead to a host compromise"
    reports = {"MITRE ATT&CK": ["TA0002:T1059"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "Find related commands within the time window and determine if the command was invoked legitimately. Examine the arguments to determine how the command was used and reach out to the user to verify the intentions.\n"
    summary_attributes = ["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"]
    tests = teleport_suspicious_commands_tests
    SUSPICIOUS_COMMANDS = {"nc", "wget"}

    def rule(self, event):
        if event.get("event") != "session.command":
            return False
        # Ignore commands without arguments
        if not event.get("argv"):
            return False
        return event.get("program") in self.SUSPICIOUS_COMMANDS

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] has executed the command [{event.get('program', '<UNKNOWN_PROGRAM>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
