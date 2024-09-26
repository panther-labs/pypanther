from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizUpdateSupportContactList(Rule):
    id = "Wiz.Update.Support.Contact.List-prototype"
    default_description = "This rule detects updates of Wiz support contact list."
    display_name = "Wiz Update Support Contact List"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://www.wiz.io/"
    default_severity = Severity.LOW
    reports = {"MITRE ATT&CK": ["TA0035:T1636.003"]}
    log_types = [LogType.WIZ_AUDIT]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") == "UpdateSupportContactList"

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="UpdateSupportContactList",
            expected_result=True,
            log={
                "id": "3a9d0fc8-8466-4e79-a2cd-014a068b985c",
                "action": "UpdateSupportContactList",
                "requestId": "fddf46ff-c69a-4f5b-a06d-c05ec95dbb21",
                "status": "SUCCESS",
                "timestamp": "2024-07-23T10:16:54.517212Z",
                "actionParameters": {
                    "input": {"patch": {"contacts": ["test.user@company.com"]}},
                    "selection": [
                        "__typename",
                        {"supportContactList": ["__typename", {"contacts": ["__typename", "id"]}]},
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
            name="UpdateSupportContactList - Fail",
            expected_result=False,
            log={
                "id": "3a9d0fc8-8466-4e79-a2cd-014a068b985c",
                "action": "UpdateSupportContactList",
                "requestId": "fddf46ff-c69a-4f5b-a06d-c05ec95dbb21",
                "status": "FAILED",
                "timestamp": "2024-07-23T10:16:54.517212Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
