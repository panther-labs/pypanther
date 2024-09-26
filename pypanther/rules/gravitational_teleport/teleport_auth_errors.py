from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class TeleportAuthErrors(Rule):
    id = "Teleport.AuthErrors-prototype"
    display_name = "Teleport SSH Auth Errors"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["SSH", "Credential Access:Brute Force"]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0006:T1110"]}
    default_description = "A high volume of SSH errors could indicate a brute-force attack"
    threshold = 10
    dedup_period_minutes = 15
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "Check that the user making the failed requests legitimately tried logging in that many times.\n"
    summary_attributes = ["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"]

    def rule(self, event):
        return bool(event.get("error")) and event.get("event") == "auth"

    def title(self, event):
        return f"A high volume of SSH errors was detected from user [{event.get('user', '<UNKNOWN_USER>')}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"

    tests = [
        RuleTest(
            name="SSH Errors",
            expected_result=True,
            log={
                "code": "T3007W",
                "error": 'ssh: principal "jack" not in the set of valid principals for given certificate: ["ec2-user"]',
                "event": "auth",
                "success": False,
                "time": "2020-08-13T18:39:42Z",
                "uid": "53e474cc-db1c-45f1-a60d-b31239e20098",
                "user": "panther",
            },
        ),
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
    ]
