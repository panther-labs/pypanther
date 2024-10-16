from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.tines import tines_alert_context


@panther_managed
class TinesTenantAuthToken(Rule):
    id = "Tines.Tenant.AuthToken-prototype"
    display_name = "Tines Tenant API Keys Added"
    log_types = [LogType.TINES_AUDIT]
    tags = ["Tines", "IAM - Credential Security"]
    default_severity = Severity.MEDIUM
    default_description = "Detects when Tines Tenant API Keys are added\n"
    default_reference = "https://www.tines.com/api/authentication"
    summary_attributes = ["user_id", "operation_name", "tenant_id", "request_ip"]
    # AuthenticationTokenDeletion does not include
    #  the scope of the deleted token.
    # Leaving deletion un-implemented for now
    # "AuthenticationTokenDeletion",
    ACTIONS = ["AuthenticationTokenCreation"]

    def rule(self, event):
        action = event.get("operation_name", "<NO_OPERATION_NAME>")
        is_tenant_token = event.deep_get("inputs", "inputs", "isServiceToken", default=False)
        return all([action in self.ACTIONS, is_tenant_token])

    def title(self, event):
        action = event.get("operation_name", "<NO_OPERATION_NAME>")
        return f"Tines: Tenant [{action}] by [{event.deep_get('user_email', default='<NO_USEREMAIL>')}]"

    def alert_context(self, event):
        a_c = tines_alert_context(event)
        a_c["token_name"] = event.deep_get("inputs", "inputs", "name", default="<NO_TOKENNAME>")
        return a_c

    def dedup(self, event):
        return f"{event.deep_get('user_id', default='<NO_USERID>')}_{event.deep_get('operation_name', default='<NO_OPERATION>')}_{event.deep_get('inputs', 'inputs', 'name', default='<NO_TOKENNAME>')}"

    tests = [
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
        RuleTest(
            name="Tines Personal API Token Created",
            expected_result=False,
            log={
                "created_at": "2023-05-18 22:54:11",
                "id": 7111111,
                "inputs": {"inputs": {"isServiceToken": False, "name": "personal-api-key"}},
                "operation_name": "AuthenticationTokenCreation",
                "request_ip": "12.12.12.12",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "tenant_id": "8888",
                "user_email": "user@company.com",
                "user_id": "17171",
                "user_name": "user at company dot com",
            },
        ),
        RuleTest(
            name="Tines Tenant API Token Created",
            expected_result=True,
            log={
                "created_at": "2023-05-18 22:54:01",
                "id": 7222222,
                "inputs": {"inputs": {"isServiceToken": True, "name": "tenant-api-key"}},
                "operation_name": "AuthenticationTokenCreation",
                "request_ip": "12.12.12.12",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "tenant_id": "8888",
                "user_email": "user@company.com",
                "user_id": "17171",
                "user_name": "user at company dot com",
            },
        ),
    ]
