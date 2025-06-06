from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TeleportNetworkScanning(Rule):
    id = "Teleport.NetworkScanning-prototype"
    display_name = "Teleport Network Scan Initiated"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["SSH", "Discovery:Network Service Discovery"]
    default_severity = Severity.MEDIUM
    default_description = (
        "A user has invoked a network scan that could potentially indicate enumeration of the network."
    )
    reports = {"MITRE ATT&CK": ["TA0007:T1046"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "Find related commands within the time window and determine if the command was invoked legitimately. Examine the arguments to determine how the command was used.\n"
    summary_attributes = ["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"]
    SCAN_COMMANDS = {"arp", "arp-scan", "fping", "nmap"}

    def rule(self, event):
        # Filter out commands
        if event.get("event") == "session.command" and (not event.get("argv")):
            return False
        # Check that the program is in our watch list
        return event.get("program") in self.SCAN_COMMANDS

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] has issued a network scan with [{event.get('program', '<UNKNOWN_PROGRAM>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"

    tests = [
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
            name="Nmap with no args",
            expected_result=False,
            log={
                "argv": [],
                "cgroup_id": 4294967672,
                "code": "T4000I",
                "ei": 16,
                "event": "session.command",
                "login": "root",
                "namespace": "default",
                "path": "/bin/nmap",
                "pid": 13555,
                "ppid": 13525,
                "program": "nmap",
                "return_code": 0,
                "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
                "sid": "a3562a0e-e57f-4273-9f69-eedb6cd029cb",
                "time": "2020-08-17T21:13:47.117Z",
                "uid": "c7f6367b-04bb-4b1d-9a3a-0497e8f4a650",
                "user": "panther",
            },
        ),
        RuleTest(
            name="Nmap with args",
            expected_result=True,
            log={
                "argv": ["-v", "-iR", "100000", "-Pn", "-p", "80"],
                "cgroup_id": 4294967672,
                "code": "T4000I",
                "ei": 16,
                "event": "session.command",
                "login": "root",
                "namespace": "default",
                "path": "/bin/nmap",
                "pid": 13555,
                "ppid": 13525,
                "program": "nmap",
                "return_code": 0,
                "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
                "sid": "a3562a0e-e57f-4273-9f69-eedb6cd029cb",
                "time": "2020-08-17T21:13:47.117Z",
                "uid": "c7f6367b-04bb-4b1d-9a3a-0497e8f4a650",
                "user": "panther",
            },
        ),
        RuleTest(
            name="Nmap running from crontab",
            expected_result=True,
            log={
                "cgroup_id": 4294967792,
                "code": "T4002I",
                "dst_addr": "67.205.137.100",
                "dst_port": 1723,
                "ei": 32,
                "event": "session.network",
                "login": "root",
                "namespace": "default",
                "pid": 15412,
                "program": "nmap",
                "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
                "sid": "a3562a0e-e57f-4273-9f69-eedb6cd029cb",
                "src_addr": "172.31.9.159",
                "time": "2020-08-18T17:37:35.883Z",
                "uid": "3e067d21-a5fb-47a3-af09-e6b9da39753c",
                "user": "panther",
                "version": 4,
            },
        ),
    ]
