from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizIntegrationUpdatedOrDeleted(Rule):
    id = "Wiz.Integration.Updated.Or.Deleted-prototype"
    default_description = "This rule detects updates and deletions of Wiz integrations."
    display_name = "Wiz Integration Updated Or Deleted"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://www.wiz.io/integrations"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    log_types = [LogType.WIZ_AUDIT]
    SUSPICIOUS_ACTIONS = ["DeleteIntegration", "UpdateIntegration"]

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
            name="DeleteIntegration",
            expected_result=True,
            log={
                "action": "DeleteIntegration",
                "actionParameters": {
                    "input": {"id": "ab4ab152-509c-425b-aa1f-601b386dfe3f"},
                    "selection": ["__typename", "_stub"],
                },
                "id": "62e490d5-484c-4c21-a2ed-b6ebcaaa5aad",
                "log_type": "auditLogEntries",
                "requestId": "bc968f65-060c-40a0-85de-3d74d02d6a54",
                "sourceIP": "12.34.56.78",
                "status": "SUCCESS",
                "timestamp": "2024-06-27 09:19:08.731355000",
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
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
            name="DeleteIntegration - Fail",
            expected_result=False,
            log={
                "action": "DeleteIntegration",
                "actionParameters": {},
                "id": "62e490d5-484c-4c21-a2ed-b6ebcaaa5aad",
                "log_type": "auditLogEntries",
                "requestId": "bc968f65-060c-40a0-85de-3d74d02d6a54",
                "sourceIP": "12.34.56.78",
                "status": "FAILED",
                "timestamp": "2024-06-27 09:19:08.731355000",
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            },
        ),
    ]
