from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import pattern_match_list
from pypanther.log_types import LogType

teleport_create_user_accounts_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Echo command",
        ExpectedResult=False,
        Log={
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
    PantherRuleTest(
        Name="Userdel command",
        ExpectedResult=True,
        Log={
            "argv": ["jacknew"],
            "cgroup_id": 4294967567,
            "code": "T4000I",
            "ei": 105,
            "event": "session.command",
            "login": "root",
            "namespace": "default",
            "path": "/sbin/userdel",
            "pid": 8931,
            "ppid": 8930,
            "program": "userdel",
            "return_code": 0,
            "server_id": "e75992b4-9e27-456f-b1c9-7a32da83c661",
            "sid": "4244c271-8069-4679-a27e-f7c18f88ce45",
            "time": "2020-08-17T18:39:26.192Z",
            "uid": "346d3f61-a010-4871-84de-897f50b18118",
            "user": "panther",
        },
    ),
]


class TeleportCreateUserAccounts(PantherRule):
    RuleID = "Teleport.CreateUserAccounts-prototype"
    DisplayName = "Teleport Create User Accounts"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["SSH", "Persistence:Create Account"]
    Reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    Severity = PantherSeverity.High
    Description = "A user has been manually created, modified, or deleted"
    DedupPeriodMinutes = 15
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "Analyze why it was manually created and delete it if necessary."
    SummaryAttributes = [
        "event",
        "code",
        "user",
        "program",
        "path",
        "return_code",
        "login",
        "server_id",
        "sid",
    ]
    Tests = teleport_create_user_accounts_tests  # user password expiry
    # change passwords for users
    # create, modify, and delete users
    USER_CREATE_PATTERNS = ["chage", "passwd", "user*"]

    def rule(self, event):
        # Filter the events
        if event.get("event") != "session.command":
            return False
        # Check that the program matches our list above
        return pattern_match_list(event.get("program", ""), self.USER_CREATE_PATTERNS)

    def title(self, event):
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] has manually modified system users on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
