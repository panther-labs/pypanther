from pypanther import LogType, Rule, RuleTest, Severity, panther_managed

duo_admin_bypass_code_created_tests: list[RuleTest] = [
    RuleTest(
        name="Bypass Create",
        expected_result=True,
        log={
            "action": "bypass_create",
            "description": '{"bypass": "", "count": 1, "valid_secs": 3600, "auto_generated": true, "remaining_uses": 1, "user_id": "D12345", "bypass_code_ids": ["A12345"]}',
            "isotimestamp": "2022-12-14 21:17:39",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:39",
            "username": "Homer Simpson",
        },
    ),
    RuleTest(
        name="Bypass Delete",
        expected_result=False,
        log={
            "action": "bypass_detele",
            "description": '{"bypass": "", "count": 1, "valid_secs": 3600, "auto_generated": true, "remaining_uses": 1, "user_id": "D12345", "bypass_code_ids": ["A12345"]}',
            "isotimestamp": "2022-12-14 21:17:39",
            "object": "target@example.io",
            "timestamp": "2022-12-14 21:17:39",
            "username": "Homer Simpson",
        },
    ),
]


@panther_managed
class DuoAdminBypassCodeCreated(Rule):
    default_description = "A Duo administrator created an MFA bypass code for an application."
    display_name = "Duo Admin Bypass Code Created"
    default_runbook = "Confirm this was authorized and necessary behavior."
    default_reference = "https://duo.com/docs/administration-users#generating-a-bypass-code"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.Bypass.Code.Created-prototype"
    tests = duo_admin_bypass_code_created_tests

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "bypass_create"

    def title(self, event):
        # If no 'dedup' function is defined, the return value of
        # this method will act as deduplication string.
        return f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] created a MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]"
