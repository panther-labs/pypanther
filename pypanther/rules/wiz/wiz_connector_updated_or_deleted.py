from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizConnectorUpdatedOrDeleted(Rule):
    id = "Wiz.Connector.Updated.Or.Deleted-prototype"
    default_description = "This rule detects updates and deletions of connectors."
    display_name = "Wiz Connector Updated Or Deleted"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://help.vulcancyber.com/en/articles/6735270-wiz-connector"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    log_types = [LogType.WIZ_AUDIT]
    SUSPICIOUS_ACTIONS = ["DeleteConnector", "UpdateConnector"]

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
            name="DeleteConnector",
            expected_result=True,
            log={
                "id": "c4fe1656-23a3-4b60-a689-d59a337c5551",
                "action": "DeleteConnector",
                "requestId": "471b9148-887a-49ff-ad83-162d7e38cf4e",
                "status": "SUCCESS",
                "timestamp": "2024-07-09T08:03:09.825336Z",
                "actionParameters": {
                    "input": {"id": "7a55031b-98f4-4a64-b77c-ad0bc9d7b54b"},
                    "selection": ["__typename", "_stub"],
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
            name="DeleteConnector - Fail",
            expected_result=False,
            log={
                "id": "c4fe1656-23a3-4b60-a689-d59a337c5551",
                "action": "DeleteConnector",
                "requestId": "471b9148-887a-49ff-ad83-162d7e38cf4e",
                "status": "FAILED",
                "timestamp": "2024-07-09T08:03:09.825336Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
