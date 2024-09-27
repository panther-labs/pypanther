from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizUpdateScannerSettings(Rule):
    id = "Wiz.Update.Scanner.Settings-prototype"
    default_description = "This rule detects updates of Wiz scanner settings."
    display_name = "Wiz Update Scanner Settings"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://www.wiz.io/academy/secret-scanning"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    log_types = [LogType.WIZ_AUDIT]

    def rule(self, event):
        if not wiz_success(event):
            return False
        return event.get("action", "ACTION_NOT_FOUND") == "UpdateScannerSettings"

    def title(self, event):
        return f"[Wiz]: [{event.get('action', 'ACTION_NOT_FOUND')}] action performed by user [{event.deep_get('user', 'name', default='USER_NAME_NOT_FOUND')}]"

    def dedup(self, event):
        return event.get("id")

    def alert_context(self, event):
        return wiz_alert_context(event)

    tests = [
        RuleTest(
            name="UpdateScannerSettings",
            expected_result=True,
            log={
                "id": "dd48b7fe-576d-453d-a0d0-1f61425b1bb7",
                "action": "UpdateScannerSettings",
                "requestId": "d5c55350-0d54-46eb-88ee-4942f80e700c",
                "status": "SUCCESS",
                "timestamp": "2024-06-18T12:09:33.985762Z",
                "actionParameters": {
                    "input": {
                        "patch": {
                            "computeResourceGroupMemberScanSamplingEnabled": True,
                            "maxComputeResourceGroupMemberScanCount": 2,
                            "prioritizeActiveComputeResourceGroupMembers": True,
                        },
                    },
                    "selection": [
                        "__typename",
                        {
                            "scannerSettings": [
                                "__typename",
                                "computeResourceGroupMemberScanSamplingEnabled",
                                "maxComputeResourceGroupMemberScanCount",
                                {"customFileDetectionList": ["__typename", "id", "url", "fileDetectionCount"]},
                            ],
                        },
                    ],
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
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
            name="UpdateScannerSettings - Fail",
            expected_result=False,
            log={
                "id": "dd48b7fe-576d-453d-a0d0-1f61425b1bb7",
                "action": "UpdateScannerSettings",
                "requestId": "d5c55350-0d54-46eb-88ee-4942f80e700c",
                "status": "FAILED",
                "timestamp": "2024-06-18T12:09:33.985762Z",
                "actionParameters": {},
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "sourceIP": "12.34.56.78",
                "serviceAccount": None,
                "user": {"id": "test.user@company.com", "name": "user@company.com"},
            },
        ),
    ]
