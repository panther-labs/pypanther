from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIATrustModification(Rule):
    id = "ZIA.Trust.Modification-prototype"
    default_description = "This rule detects when SAML authentication was enabled/disabled."
    display_name = "ZIA Trust Modification"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://help.zscaler.com/zia/configuring-saml"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0004:T1484.002"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        saml_enabled_pre = event.deep_get("event", "preaction", "samlEnabled", default="<PRE_SAML_STATUS_NOT_FOUND>")
        saml_enabled_post = event.deep_get("event", "postaction", "samlEnabled", default="<POST_SAML_STATUS_NOT_FOUND>")
        if action == "UPDATE" and category == "ADMINISTRATOR_MANAGEMENT" and (saml_enabled_pre != saml_enabled_post):
            return True
        return False

    def title(self, event):
        return f"[Zscaler.ZIA]: SAML configuration was changed by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Administration > Administration Management > Enable SAML Authentication",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ADMINISTRATOR_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {"certFilename": "abc.crt", "productId": 0, "samlEnabled": True},
                    "preaction": {"productId": 0, "samlEnabled": False},
                    "recordid": "332",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_SAML",
                    "time": "2024-10-22 22:13:23.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration > Administration Management > Disable SAML Authentication",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ADMINISTRATOR_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {"certFilename": "abc.crt", "productId": 0, "samlEnabled": False},
                    "preaction": {"productId": 0, "samlEnabled": True},
                    "recordid": "332",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_SAML",
                    "time": "2024-10-22 22:13:23.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
