from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizUpdateLoginSettings(Rule):
    id = "Wiz.Update.Login.Settings-prototype"
    default_description = "This rule detects updates of Wiz login settings."
    display_name = "Wiz Update Login Settings"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://support.wiz.io/hc/en-us/categories/5311977085340-User-Management"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0006:T1556"]}
    log_types = [LogType.WIZ_AUDIT]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") == "UpdateLoginSettings"

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="UpdateLoginSettings",
            expected_result=True,
            log={
                "id": "f77a8e1e-5674-42d1-9f1e-8a259dc736cd",
                "action": "UpdateLoginSettings",
                "requestId": "417f1751-bcc1-4d38-86aa-eb781790bdd6",
                "status": "SUCCESS",
                "timestamp": "2024-06-16T13:14:22.291227Z",
                "actionParameters": {
                    "input": {"patch": {"approvedUserDomains": ["abc.com"]}},
                    "selection": ["__typename", {"loginSettings": ["__typename", "approvedUserDomains"]}],
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "<redacted>", "name": "user@company.com"},
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
            name="UpdateLoginSettings - Fail",
            expected_result=False,
            log={
                "id": "f77a8e1e-5674-42d1-9f1e-8a259dc736cd",
                "action": "UpdateLoginSettings",
                "requestId": "417f1751-bcc1-4d38-86aa-eb781790bdd6",
                "status": "FAILED",
                "timestamp": "2024-06-16T13:14:22.291227Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "<redacted>", "name": "user@company.com"},
            },
        ),
    ]
