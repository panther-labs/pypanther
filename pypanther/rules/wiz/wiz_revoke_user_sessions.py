from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizRevokeUserSessions(Rule):
    id = "Wiz.Revoke.User.Sessions-prototype"
    default_description = "This rule detects user sessions revoked."
    display_name = "Wiz Revoke User Sessions"
    default_runbook = (
        "Verify that this change was planned. If not, revoke all the sessions of the account and change its credentials"
    )
    default_reference = (
        "https://www.wiz.io/blog/storm-0558-compromised-microsoft-key-enables-authentication-of-countless-micr"
    )
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    log_types = [LogType.WIZ_AUDIT]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") == "RevokeUserSessions"

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="RevokeUserSessions",
            expected_result=True,
            log={
                "id": "07fdb41e-e83d-46e2-814a-6cebc47acf97",
                "action": "RevokeUserSessions",
                "requestId": "5fa96b8f-2c85-4c2d-b0f9-d4a4307ea8a7",
                "status": "SUCCESS",
                "timestamp": "2024-07-31T17:55:29.239928Z",
                "actionParameters": {"input": {"id": "<redacted>"}, "selection": ["__typename", "_stub"]},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
        RuleTest(
            name="CreateUser",
            expected_result=False,
            log={
                "id": "220d23be-f07c-4d97-b4a6-87ad04eddb14",
                "action": "CreateUser",
                "requestId": "0d9521b2-c3f8-4a73-bf7c-20257788752e",
                "status": "SUCCESS",
                "timestamp": "2024-07-29T09:40:15.66643Z",
                "actionParameters": {
                    "input": {
                        "assignedProjectIds": None,
                        "email": "testy@company.com",
                        "expiresAt": None,
                        "name": "Test User",
                        "role": "GLOBAL_ADMIN",
                    },
                    "selection": ["__typename", {"user": ["__typename", "id"]}],
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "8.8.8.8",
                "serviceAccount": None,
                "user": {"id": "someuser@company.com", "name": "someuser@company.com"},
            },
        ),
        RuleTest(
            name="RevokeUserSessions - Fail",
            expected_result=False,
            log={
                "id": "07fdb41e-e83d-46e2-814a-6cebc47acf97",
                "action": "RevokeUserSessions",
                "requestId": "5fa96b8f-2c85-4c2d-b0f9-d4a4307ea8a7",
                "status": "FAILED",
                "timestamp": "2024-07-31T17:55:29.239928Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
