from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIAPasswordExpiration(Rule):
    id = "ZIA.Password.Expiration-prototype"
    default_description = "This rule detects when password expiration eas set/removed."
    display_name = "ZIA Password Expiration"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://help.zscaler.com/zia/configuring-password-expiration"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0007:T1201"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        password_exp_pre = event.deep_get(
            "event",
            "preaction",
            "passwordExpirationEnabled",
            default="<PRE_PASSWORD_EXPIRATION_NOT_FOUND>",
        )
        password_exp_post = event.deep_get(
            "event",
            "postaction",
            "passwordExpirationEnabled",
            default="<POST_PASSWORD_EXPIRATION_NOT_FOUND>",
        )
        if action == "UPDATE" and category == "LOGIN" and (password_exp_pre != password_exp_post):
            return True
        return False

    def title(self, event):
        return f"[Zscaler.ZIA]: SAML configuration was changed by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Administration Management > Administrator Management > Set Password Expriration 180 days",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "LOGIN",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {"passwordExpirationEnabled": True, "passwordExpiryDays": 180},
                    "preaction": {"passwordExpirationEnabled": False, "passwordExpiryDays": 180},
                    "recordid": "331",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "PASSWORD_EXPIRY",
                    "time": "2024-10-22 22:12:25.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration Management > Administrator Management > Remove Password Expriration",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "LOGIN",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {"passwordExpirationEnabled": False, "passwordExpiryDays": 180},
                    "preaction": {"passwordExpirationEnabled": True, "passwordExpiryDays": 180},
                    "recordid": "331",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "PASSWORD_EXPIRY",
                    "time": "2024-10-22 22:12:25.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
