from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizRuleChange(Rule):
    id = "Wiz.Rule.Change-prototype"
    default_description = "This rule detects creations, updates and deletions of Wiz rules."
    display_name = "Wiz Rule Change"
    default_runbook = "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again. If needed, review the privileges of existing accounts."
    default_reference = "https://www.wiz.io/blog/custom-runtime-rules-and-response-policies"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.001"]}
    log_types = [LogType.WIZ_AUDIT]  # we have no sample log for such event, but I suppose there should be one
    SUSPICIOUS_ACTIONS = [
        "DeleteAutomationRule",
        "UpdateAutomationRule",
        "DeleteCloudEventRule",
        "UpdateCloudEventRule",
        "DeleteCloudConfigurationRule",
        "UpdateCloudConfigurationRule",
        "DeleteHostConfigurationRule",
        "UpdateHostConfigurationRule",
        "CreateIgnoreRule",
        "DeleteIgnoreRule",
        "UpdateIgnoreRule",
        "CreateMalwareExclusion",
        "UpdateMalwareExclusion",
    ]

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

    def severity(self, event):
        action = event.get("action", "ACTION_NOT_FOUND")
        if "Delete" in action:
            return "High"
        if "Create" in action:
            return "Low"
        return "Default"

    tests = [
        RuleTest(
            name="DeleteCloudConfigurationRule",
            expected_result=True,
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
            name="DeleteCloudConfigurationRule - Fail",
            expected_result=False,
            log={
                "action": "DeleteCloudConfigurationRule",
                "id": "12345-0301-491d-9fe6-12345",
                "log_type": "auditLogEntries",
                "requestid": "12345-c18f-4ce0-9288-12345",
                "serviceaccount": None,
                "sourceip": "8.8.8.8",
                "status": "FAILED",
                "timestamp": "2024-03-24 10:58:31.347",
                "user": {"id": "testy@company.com", "name": "testy@company.com"},
                "useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            },
        ),
    ]
