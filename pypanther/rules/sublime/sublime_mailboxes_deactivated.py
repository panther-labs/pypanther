from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.sublime import sublime_alert_context


@panther_managed
class SublimeMailboxDeactivated(Rule):
    default_description = "A Sublime User disabled some mailbox(es)."
    display_name = "Sublime Mailbox Deactivated"
    default_runbook = "Assess if this was done by the user for a valid business reason. Be vigilant to re-enable the mailboxes if it's in the best security interest for your organization's security posture."
    default_reference = "https://docs.sublime.security/docs/add-message-source"
    default_severity = Severity.MEDIUM
    alert_title = "Sublime message mailbox(es) were deactivated"
    log_types = [LogType.SUBLIME_AUDIT]
    id = "Sublime.Mailbox.Deactivated-prototype"
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}

    def rule(self, event):
        return event.get("type") == "message_source.deactivate_mailboxes"

    def alert_context(self, event):
        return sublime_alert_context(event)

    tests = [
        RuleTest(
            name="Other Events",
            expected_result=False,
            log={
                "created_at": "2024-09-09 19:33:34.237078000",
                "created_by": {
                    "active": True,
                    "created_at": "2024-08-28 22:05:15.715644000",
                    "email_address": "john.doe@sublime.security",
                    "first_name": "John",
                    "google_oauth_user_id": "",
                    "id": "cd3aedfe-a61f-4e0e-ba30-14dcc7883316",
                    "is_enrolled": True,
                    "last_name": "Doe",
                    "microsoft_oauth_user_id": "",
                    "role": "admin",
                    "updated_at": "2024-08-28 22:05:15.715644000",
                },
                "data": {
                    "request": {
                        "authentication_method": "user_session",
                        "body": '{"mailbox_ids":["493c6e21-7787-419b-bada-7c4f50cbb932"]}',
                        "id": "73444211-31af-42d8-99b4-34a139cf7d4a",
                        "ip": "1.2.3.4",
                        "method": "POST",
                        "path": "/v1/message-sources/febb5bf4-2ead-47b1-b467-0ac729bf6871/deactivate",
                        "query": {},
                        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                    },
                },
                "id": "084732e5-7704-4bbe-ab5a-77f1aa65a737",
                "type": "message_source.deactivate",
            },
        ),
        RuleTest(
            name="Mailbox Deactivated",
            expected_result=True,
            log={
                "created_at": "2024-09-09 19:33:34.237078000",
                "created_by": {
                    "active": True,
                    "created_at": "2024-08-28 22:05:15.715644000",
                    "email_address": "john.doe@sublime.security",
                    "first_name": "John",
                    "google_oauth_user_id": "",
                    "id": "cd3aedfe-a61f-4e0e-ba30-14dcc7883316",
                    "is_enrolled": True,
                    "last_name": "Doe",
                    "microsoft_oauth_user_id": "",
                    "role": "admin",
                    "updated_at": "2024-08-28 22:05:15.715644000",
                },
                "data": {
                    "request": {
                        "authentication_method": "user_session",
                        "body": '{"mailbox_ids":["493c6e21-7787-419b-bada-7c4f50cbb932"]}',
                        "id": "73444211-31af-42d8-99b4-34a139cf7d4a",
                        "ip": "1.2.3.4",
                        "method": "POST",
                        "path": "/v1/message-sources/febb5bf4-2ead-47b1-b467-0ac729bf6871/deactivate",
                        "query": {},
                        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                    },
                },
                "id": "084732e5-7704-4bbe-ab5a-77f1aa65a737",
                "type": "message_source.deactivate_mailboxes",
            },
        ),
    ]
