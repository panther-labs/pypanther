from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.wiz import wiz_alert_context, wiz_success


@panther_managed
class WizSAMLIdentityProviderChange(Rule):
    id = "Wiz.SAML.Identity.Provider.Change-prototype"
    default_description = "This rule detects creations, updates and deletions of SAML identity providers."
    display_name = "Wiz SAML Identity Provider Change"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://support.wiz.io/hc/en-us/articles/5644029716380-Single-Sign-on-SSO-Overview"
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0004:T1484.002"]}
    log_types = [LogType.WIZ_AUDIT]
    SUSPICIOUS_ACTIONS = [
        "UpdateSAMLIdentityProvider",
        "DeleteSAMLIdentityProvider",
        "CreateSAMLIdentityProvider",
        "ModifySAMLIdentityProviderGroupMappings",
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

    tests = [
        RuleTest(
            name="DeleteSAMLIdentityProvider",
            expected_result=True,
            log={
                "id": "0fc891d1-c2e3-4db2-b896-7af27964c71b",
                "action": "DeleteSAMLIdentityProvider",
                "requestId": "eec733c5-175c-4d0c-8b65-b9344f223a36",
                "status": "SUCCESS",
                "timestamp": "2024-07-12T08:59:33.946633Z",
                "actionParameters": {"input": {"id": "<redacted>"}, "selection": ["_stub"]},
                "userAgent": "Wiz-Terraform-Provider/1.13.3433",
                "sourceIP": "12.34.56.78",
                "serviceAccount": {"id": "<redacted>", "name": "test-graphql-api"},
                "user": None,
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
            name="DeleteSAMLIdentityProvider - Fail",
            expected_result=False,
            log={
                "id": "0fc891d1-c2e3-4db2-b896-7af27964c71b",
                "action": "DeleteSAMLIdentityProvider",
                "requestId": "eec733c5-175c-4d0c-8b65-b9344f223a36",
                "status": "FAILED",
                "timestamp": "2024-07-12T08:59:33.946633Z",
                "actionParameters": {},
                "userAgent": "Wiz-Terraform-Provider/1.13.3433",
                "sourceIP": "12.34.56.78",
                "serviceAccount": {"id": "<redacted>", "name": "test-graphql-api"},
                "user": None,
            },
        ),
    ]
