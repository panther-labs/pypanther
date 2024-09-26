from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizRotateServiceAccountSecret(Rule):
    id = "Wiz.Rotate.Service.Account.Secret-prototype"
    default_description = "This rule detects service account secrets rotations."
    display_name = "Wiz Rotate Service Account Secret"
    default_runbook = "Verify the action was planned."
    default_reference = "https://www.wiz.io/academy/kubernetes-secrets"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0001:T1078.004"]}
    log_types = [LogType.WIZ_AUDIT]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") == "RotateServiceAccountSecret"

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="RotateServiceAccountSecret",
            expected_result=True,
            log={
                "id": "d78f5ef1-3814-4d47-b789-0e43d4cc0ef2",
                "action": "RotateServiceAccountSecret",
                "requestId": "2303f545-a219-4c6d-b217-b76bb5e06a20",
                "status": "SUCCESS",
                "timestamp": "2024-07-16T10:47:43.562393Z",
                "actionParameters": {
                    "ID": "rsao...<redacted>",
                    "selection": [
                        "__typename",
                        {
                            "serviceAccount": [
                                "__typename",
                                "id",
                                "enabled",
                                "name",
                                "clientId",
                                "scopes",
                                "lastRotatedAt",
                                "expiresAt",
                                "description",
                                {"integration": ["__typename", "id"]},
                                "clientSecret",
                            ],
                        },
                    ],
                },
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
            name="RotateServiceAccountSecret - Fail",
            expected_result=False,
            log={
                "id": "d78f5ef1-3814-4d47-b789-0e43d4cc0ef2",
                "action": "RotateServiceAccountSecret",
                "requestId": "2303f545-a219-4c6d-b217-b76bb5e06a20",
                "status": "FAILED",
                "timestamp": "2024-07-16T10:47:43.562393Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
