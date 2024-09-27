from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizServiceAccountChange(Rule):
    id = "Wiz.Service.Account.Change-prototype"
    default_description = "This rule detects creations, updates and deletions of service accounts."
    display_name = "Wiz Service Account Change"
    default_runbook = (
        "Confirm this user acted with valid business intent and determine whether this activity was authorized."
    )
    default_reference = "https://www.wiz.io/blog/non-human-identities-dashboard"
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0001:T1078.004"]}
    log_types = [LogType.WIZ_AUDIT]
    SUSPICIOUS_ACTIONS = ["CreateServiceAccount", "DeleteServiceAccount", "UpdateServiceAccount"]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") in self.SUSPICIOUS_ACTIONS

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="DeleteServiceAccount",
            expected_result=True,
            log={
                "id": "ac5630ca-2dd9-40a5-8137-140443cd8087",
                "action": "DeleteServiceAccount",
                "requestId": "a9291dc4-a17c-4af7-bb9e-17905082221f",
                "status": "SUCCESS",
                "timestamp": "2024-07-09T14:16:02.836387Z",
                "actionParameters": {"input": {"id": "rsao...<redacted>"}, "selection": ["__typename", "_stub"]},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"__typename": "User", "id": "test.user@company.com", "name": "user@company.com"},
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
            name="DeleteServiceAccount - Fail",
            expected_result=False,
            log={
                "id": "ac5630ca-2dd9-40a5-8137-140443cd8087",
                "action": "DeleteServiceAccount",
                "requestId": "a9291dc4-a17c-4af7-bb9e-17905082221f",
                "status": "FAILED",
                "timestamp": "2024-07-09T14:16:02.836387Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"__typename": "User", "id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
