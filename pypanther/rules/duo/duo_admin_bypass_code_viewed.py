from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DuoAdminBypassCodeViewed(Rule):
    default_description = "An administrator viewed the MFA bypass code for a user."
    display_name = "Duo Admin Bypass Code Viewed"
    default_reference = "https://duo.com/docs/adminapi"
    default_runbook = "Confirm this behavior is authorized. The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. You should not share it with unauthorized individuals or email it to anyone under any circumstances!"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.Bypass.Code.Viewed-prototype"

    def rule(self, event):
        # Return True to match the log event and trigger an alert.
        return event.get("action", "") == "bypass_view"

    def title(self, event):
        # If no 'dedup' function is defined, the return value
        # of this method will act as deduplication string.
        return f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed an MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]."

    tests = [
        RuleTest(
            name="Bypass View",
            expected_result=True,
            log={
                "action": "bypass_view",
                "description": '{"user_id": "D1234", "bypass_code_id": "D5678"}',
                "isotimestamp": "2022-12-14 21:17:54",
                "object": "target@example.io",
                "timestamp": "2022-12-14 21:17:54",
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
