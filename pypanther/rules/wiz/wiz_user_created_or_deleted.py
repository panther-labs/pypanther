from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizUserCreatedOrDeleted(Rule):
    id = "Wiz.User.Created.Or.Deleted-prototype"
    default_description = "This rule detects creations and deletions of Wiz users."
    display_name = "Wiz User Created Or Deleted"
    default_runbook = "Verify that this change was planned."
    default_reference = "https://support.wiz.io/hc/en-us/categories/5311977085340-User-Management"
    default_severity = Severity.LOW
    reports = {"MITRE ATT&CK": ["TA0003:T1136.003", "TA0005:T1070.009"]}
    log_types = [LogType.WIZ_AUDIT]
    SUSPICIOUS_ACTIONS = ["CreateUser", "DeleteUser"]

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
            name="Deleted rule",
            expected_result=False,
            log={
                "action": "DeleteCloudConfigurationRule",
                "actionparameters": {
                    "input": {"id": "12345-3fd7-4063-8e06-12345"},
                    "selection": ["__typename", "_stub"],
                },
                "id": "12345-0301-491d-9fe6-12345",
                "log_type": "auditLogEntries",
                "requestid": "12345-c18f-4ce0-9288-12345",
                "serviceaccount": None,
                "sourceip": "8.8.8.8",
                "status": "SUCCESS",
                "timestamp": "2024-03-24 10:58:31.347",
                "user": {"id": "testy@company.com", "name": "testy@company.com"},
                "useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            },
        ),
        RuleTest(
            name="CreateUser",
            expected_result=True,
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
            name="CreateUser - Fail",
            expected_result=False,
            log={
                "id": "220d23be-f07c-4d97-b4a6-87ad04eddb14",
                "action": "CreateUser",
                "requestId": "0d9521b2-c3f8-4a73-bf7c-20257788752e",
                "status": "FAILED",
                "timestamp": "2024-07-29T09:40:15.66643Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "8.8.8.8",
                "serviceAccount": None,
                "user": {"id": "someuser@company.com", "name": "someuser@company.com"},
            },
        ),
    ]
