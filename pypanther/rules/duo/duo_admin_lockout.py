import json

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

duo_admin_lockout_tests: list[RuleTest] = [
    RuleTest(
        name="Admin lockout- invalid json",
        expected_result=True,
        log={
            "action": "admin_lockout",
            "description": '"message": "Admin temporarily locked out due to too many passcode attempts."',
            "isotimestamp": "2022-12-14 21:02:03",
            "timestamp": "2022-12-14 21:02:03",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Admin lockout- valid json",
        expected_result=True,
        log={
            "action": "admin_lockout",
            "description": '{"message": "Admin temporarily locked out due to too many passcode attempts."}',
            "isotimestamp": "2022-12-14 21:02:03",
            "timestamp": "2022-12-14 21:02:03",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Bypass Create",
        expected_result=False,
        log={
            "action": "bypass_create",
            "description": '{"bypass": "", "count": 1, "valid_secs": 3600, "auto_generated": true, "remaining_uses": 1, "user_id": "D12345", "bypass_code_ids": ["A12345"]}',
            "isotimestamp": "2022-12-14 21:17:39",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:39",
            "username": "Homer Simpson",
        },
    ),
]


@panther_managed
class DuoAdminLockout(Rule):
    default_description = "Alert when a duo administrator is locked out of their account."
    display_name = "Duo Admin Lockout"
    default_reference = "https://duo.com/docs/adminapi"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.Lockout-prototype"
    tests = duo_admin_lockout_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "admin_lockout"

    def title(self, event):
        # If no 'dedup' function is defined, the return value
        # of this method will act as deduplication string.
        try:
            desc = json.loads(event.get("description", {}))
            message = desc.get("message", "<NO_MESSAGE_FOUND>")[:-1]
        except ValueError:
            message = "Invalid Json"
        return f"Duo Admin [{event.get('username', '<NO_USER_FOUND>')}] is locked out. Reason: [{message}]."
