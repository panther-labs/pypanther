from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizUpdateIPRestrictions(Rule):
    id = "Wiz.Update.IP.Restrictions-prototype"
    default_description = "This rule detects updates of IP restrictions."
    display_name = "Wiz Update IP Restrictions"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = (
        "https://support.wix.com/en/article/wix-enterprise-managing-access-to-your-sites-using-ip-allowlisting"
    )
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0003:T1556.009"]}
    log_types = [LogType.WIZ_AUDIT]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") == "UpdateIPRestrictions"

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="UpdateIPRestrictions",
            expected_result=True,
            log={
                "id": "66aa29d4-7a2e-4b09-a46c-ff72b2c55425",
                "action": "UpdateIPRestrictions",
                "requestId": "22681d26-0ba0-4730-8f05-0b2c3adefe1b",
                "status": "SUCCESS",
                "timestamp": "2024-07-31T18:10:33.436381Z",
                "actionParameters": {
                    "input": {"serviceAccountAccessAllowedIPs": ["0.0.0.0/0"], "userAccessAllowedIPs": []},
                    "selection": [
                        "__typename",
                        {"ipRestrictions": ["__typename", "userAccessAllowedIPs", "serviceAccountAccessAllowedIPs"]},
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
            name="UpdateIPRestrictions - Fail",
            expected_result=False,
            log={
                "id": "66aa29d4-7a2e-4b09-a46c-ff72b2c55425",
                "action": "UpdateIPRestrictions",
                "requestId": "22681d26-0ba0-4730-8f05-0b2c3adefe1b",
                "status": "FAILED",
                "timestamp": "2024-07-31T18:10:33.436381Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
