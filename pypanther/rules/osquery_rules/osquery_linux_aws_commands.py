import shlex

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

osquery_linux_aws_command_executed_tests: list[RuleTest] = [
    RuleTest(
        name="AWS command executed on MacOS",
        expected_result=False,
        log={
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
    RuleTest(
        name="AWS command executed",
        expected_result=True,
        log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "columns": {"command": "aws s3 ls", "uid": "1000", "directory": "/home/ubuntu", "username": "ubuntu"},
        },
    ),
    RuleTest(
        name="Tail command executed",
        expected_result=False,
        log={
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
    RuleTest(
        name="Command with quote executed",
        expected_result=False,
        log={
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
    RuleTest(
        name="Invalid command ignored",
        expected_result=False,
        log={
            "name": "pack_incident-response_shell_history",
            "action": "added",
            "columns": {"command": "unopened '", "uid": "1000", "directory": "/home/ubuntu", "username": "ubuntu"},
        },
    ),
]


@panther_managed
class OsqueryLinuxAWSCommandExecuted(Rule):
    id = "Osquery.Linux.AWSCommandExecuted-prototype"
    display_name = "AWS command executed on the command line"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "Linux", "Execution:User Execution"]
    reports = {"MITRE ATT&CK": ["TA0002:T1204"]}
    default_severity = Severity.MEDIUM
    default_description = "An AWS command was executed on a Linux instance"
    default_runbook = "See which other commands were executed, and then remove IAM role causing the access"
    default_reference = "https://attack.mitre.org/techniques/T1078/"
    summary_attributes = ["name", "action"]
    tests = osquery_linux_aws_command_executed_tests
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
