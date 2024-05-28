import shlex
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

osquery_linux_aws_command_executed_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="AWS command executed on MacOS",
        ExpectedResult=False,
        Log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "decorations": {"platform": "darwin"},
            "columns": {
                "command": "aws sts get-caller-identity",
                "uid": "1000",
                "directory": "/home/ubuntu",
                "username": "ubuntu",
            },
        },
    ),
    PantherRuleTest(
        Name="AWS command executed",
        ExpectedResult=True,
        Log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "columns": {
                "command": "aws s3 ls",
                "uid": "1000",
                "directory": "/home/ubuntu",
                "username": "ubuntu",
            },
        },
    ),
    PantherRuleTest(
        Name="Tail command executed",
        ExpectedResult=False,
        Log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "columns": {
                "command": "tail -f /var/log/all",
                "uid": "1000",
                "directory": "/home/ubuntu",
                "username": "ubuntu",
            },
        },
    ),
    PantherRuleTest(
        Name="Command with quote executed",
        ExpectedResult=False,
        Log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "columns": {
                "command": "git commit -m 'all done'",
                "uid": "1000",
                "directory": "/home/ubuntu",
                "username": "ubuntu",
            },
        },
    ),
    PantherRuleTest(
        Name="Invalid command ignored",
        ExpectedResult=False,
        Log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "columns": {
                "command": "unopened '",
                "uid": "1000",
                "directory": "/home/ubuntu",
                "username": "ubuntu",
            },
        },
    ),
]


class OsqueryLinuxAWSCommandExecuted(PantherRule):
    RuleID = "Osquery.Linux.AWSCommandExecuted-prototype"
    DisplayName = "AWS command executed on the command line"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "Linux", "Execution:User Execution"]
    Reports = {"MITRE ATT&CK": ["TA0002:T1204"]}
    Severity = PantherSeverity.Medium
    Description = "An AWS command was executed on a Linux instance"
    Runbook = "See which other commands were executed, and then remove IAM role causing the access"
    Reference = "https://attack.mitre.org/techniques/T1078/"
    SummaryAttributes = ["name", "action"]
    Tests = osquery_linux_aws_command_executed_tests
    PLATFORM_IGNORE_LIST = {"darwin"}

    def rule(self, event):
        # Filter out irrelevant logs & systems
        if (
            event.get("action") != "added"
            or "shell_history" not in event.get("name")
            or deep_get(event, "decorations", "platform") in self.PLATFORM_IGNORE_LIST
        ):
            return False
        command = deep_get(event, "columns", "command")
        if not command:
            return False
        try:
            command_args = shlex.split(command)
        except ValueError:
            # "No escaped character" or "No closing quotation", probably an invalid command
            return False
        if command_args[0] == "aws":
            return True
        return False

    def title(self, event):
        return f"User [{deep_get(event, 'columns', 'username', default='<UNKNOWN_USER>')}] issued an aws-cli command on [{event.get('hostIdentifier', '<UNKNOWN_HOST>')}]"
