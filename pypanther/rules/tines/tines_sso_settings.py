from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.tines import tines_alert_context


@panther_managed
class TinesSSOSettings(Rule):
    id = "Tines.SSO.Settings-prototype"
    display_name = "Tines SSO Settings"
    log_types = [LogType.TINES_AUDIT]
    tags = ["Tines", "IAM - Credential Security"]
    default_severity = Severity.HIGH
    default_description = "Detects when Tines SSO settings are changed\n"
    default_reference = "https://www.tines.com/docs/admin/single-sign-on"
    summary_attributes = ["user_id", "operation_name", "tenant_id", "request_ip"]
    ACTIONS = ["SsoConfigurationDefaultSet", "SsoConfigurationOidcSet", "SsoConfigurationSamlSet"]

    def rule(self, event):
        action = event.get("operation_name", "<NO_OPERATION_NAME>")
        return action in self.ACTIONS

    def title(self, event):
        action = event.get("operation_name", "<NO_OPERATION_NAME>")
        return f"Tines: [{action}] Setting changed by [{event.deep_get('user_email', default='<NO_USEREMAIL>')}]"

    def alert_context(self, event):
        return tines_alert_context(event)

    def dedup(self, event):
        return f"{event.deep_get('user_id', default='<NO_USERID>')}_{event.deep_get('operation_name', default='<NO_OPERATION>')}"

    tests = [
        RuleTest(
            name="Tines SsoConfigurationSamlSet",
            expected_result=True,
            log={
                "created_at": "2023-05-16 23:26:46",
                "id": 1111111,
                "inputs": {
                    "domainId": "REDACTED",
                    "fingerprint": "REDACTED",
                    "idpCertificate": "REDACTED",
                    "targetUrl": "REDACTED",
                },
                "operation_name": "SsoConfigurationSamlSet",
                "request_ip": "12.12.12.12",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "tenant_id": "8888",
                "user_email": "user@company.com",
                "user_id": "17171",
                "user_name": "user at company dot com",
            },
        ),
        RuleTest(
            name="Tines Login",
            expected_result=False,
            log={
                "created_at": "2023-05-17 14:45:19",
                "id": 7888888,
                "operation_name": "Login",
                "request_ip": "12.12.12.12",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "tenant_id": "8888",
                "user_email": "user@company.com",
                "user_id": "17171",
                "user_name": "user at company dot com",
            },
        ),
    ]
