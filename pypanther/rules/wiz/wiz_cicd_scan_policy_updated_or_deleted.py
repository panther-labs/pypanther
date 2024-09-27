from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizCICDScanPolicyUpdatedOrDeleted(Rule):
    id = "Wiz.CICD.Scan.Policy.Updated.Or.Deleted-prototype"
    default_description = "This rule detects updates and deletions of CICD scan policies."
    display_name = "Wiz CICD Scan Policy Updated Or Deleted"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://www.wiz.io/academy/ci-cd-security-best-practices"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    log_types = [LogType.WIZ_AUDIT]
    SUSPICIOUS_ACTIONS = ["DeleteCICDScanPolicy", "UpdateCICDScanPolicy"]

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
            name="DeleteCICDScanPolicy",
            expected_result=True,
            log={
                "action": "DeleteCICDScanPolicy",
                "actionparameters": {"input": {"id": "12345-cd1f-4a4b-b3e4-12345"}},
                "id": "12345-de20-4e00-b958-12345",
                "log_type": None,
                "requestid": "12345-284b-4166-aea7-12345",
                "serviceaccount": None,
                "sourceip": "8.8.8.8",
                "status": "SUCCESS",
                "timestamp": "2023-09-01 14:27:42.694",
                "user": {"id": "test@company.com", "name": "test@company.com"},
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
            name="DeleteCICDScanPolicy - Fail",
            expected_result=False,
            log={
                "action": "DeleteCICDScanPolicy",
                "actionparameters": {},
                "id": "12345-de20-4e00-b958-12345",
                "log_type": None,
                "requestid": "12345-284b-4166-aea7-12345",
                "serviceaccount": None,
                "sourceip": "8.8.8.8",
                "status": "FAILED",
                "timestamp": "2023-09-01 14:27:42.694",
                "user": {"id": "test@company.com", "name": "test@company.com"},
            },
        ),
    ]
