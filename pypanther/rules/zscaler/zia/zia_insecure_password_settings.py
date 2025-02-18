from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIAInsecurePasswordSettings(Rule):
    id = "ZIA.Insecure.Password.Settings-prototype"
    default_description = "This rule detects when password settings are insecure."
    display_name = "ZIA Insecure Password Settings"
    default_runbook = "Set the secure password configurations."
    default_reference = "https://help.zscaler.com/zia/customizing-your-admin-account-settings"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1556.009"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        auth_frequency = event.deep_get("event", "postaction", "authFrequency", default="<AUTH_FREQUENCY_NOT_FOUND>")
        password_expiry = event.deep_get("event", "postaction", "passwordExpiry", default="<PASSWORD_EXPIRY_NOT_FOUND>")
        password_strength = event.deep_get(
            "event",
            "postaction",
            "passwordStrength",
            default="<PASSWORD_STRENGTH_NOT_FOUND>",
        )
        if auth_frequency == "PERMANENT_COOKIE" or password_expiry == "NEVER" or password_strength == "NONE":  # nosec bandit B105
            # nosec bandit B105
            return True
        return False

    def dedup(self, event):
        return event.deep_get("event", "adminid", default="<ADMIN_ID_NOT_FOUND>")

    def title(self, event):
        return f"[Zscaler.ZIA]: Password settings are insecure for admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Permanent cookie",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "AUTHENTICATION_SETTINGS",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "authFrequency": "PERMANENT_COOKIE",
                        "autoProvision": False,
                        "directorySyncMigrateToScimEnabled": False,
                        "kerberosEnabled": False,
                        "mobileAdminSamlIdpEnabled": False,
                        "oneTimeAuth": "OTP_DISABLED",
                        "orgAuthType": "SAFECHANNEL_DIR",
                        "passwordExpiry": "NEVER",
                        "passwordStrength": "NONE",
                        "samlEnabled": False,
                    },
                    "preaction": {
                        "authFrequency": "DAILY_COOKIE",
                        "autoProvision": False,
                        "directorySyncMigrateToScimEnabled": False,
                        "kerberosEnabled": False,
                        "mobileAdminSamlIdpEnabled": False,
                        "oneTimeAuth": "OTP_DISABLED",
                        "orgAuthType": "SAFECHANNEL_DIR",
                        "passwordExpiry": "NEVER",
                        "passwordStrength": "NONE",
                        "samlEnabled": False,
                    },
                    "recordid": "356",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "AUTH_SETTINGS_PROFILE",
                    "time": "2024-11-04 16:29:24.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Password expiry - never",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "AUTHENTICATION_SETTINGS",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "authFrequency": "DAILY_COOKIE",
                        "autoProvision": False,
                        "directorySyncMigrateToScimEnabled": False,
                        "kerberosEnabled": False,
                        "mobileAdminSamlIdpEnabled": False,
                        "oneTimeAuth": "OTP_LINK",
                        "orgAuthType": "SAFECHANNEL_DIR",
                        "passwordExpiry": "NEVER",
                        "passwordStrength": "NONE",
                        "samlEnabled": False,
                    },
                    "preaction": {
                        "authFrequency": "DAILY_COOKIE",
                        "autoProvision": False,
                        "directorySyncMigrateToScimEnabled": False,
                        "kerberosEnabled": False,
                        "mobileAdminSamlIdpEnabled": False,
                        "oneTimeAuth": "OTP_DISABLED",
                        "orgAuthType": "SAFECHANNEL_DIR",
                        "passwordExpiry": "NEVER",
                        "passwordStrength": "NONE",
                        "samlEnabled": False,
                    },
                    "recordid": "357",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "AUTH_SETTINGS_PROFILE",
                    "time": "2024-11-04 16:29:40.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Password strength - none",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "AUTHENTICATION_SETTINGS",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "authFrequency": "DAILY_COOKIE",
                        "autoProvision": False,
                        "directorySyncMigrateToScimEnabled": False,
                        "kerberosEnabled": False,
                        "mobileAdminSamlIdpEnabled": False,
                        "oneTimeAuth": "OTP_DISABLED",
                        "orgAuthType": "SAFECHANNEL_DIR",
                        "passwordExpiry": "SIX_MONTHS",
                        "passwordStrength": "NONE",
                        "samlEnabled": False,
                    },
                    "preaction": {
                        "authFrequency": "DAILY_COOKIE",
                        "autoProvision": False,
                        "directorySyncMigrateToScimEnabled": False,
                        "kerberosEnabled": False,
                        "mobileAdminSamlIdpEnabled": False,
                        "oneTimeAuth": "OTP_DISABLED",
                        "orgAuthType": "SAFECHANNEL_DIR",
                        "passwordExpiry": "NEVER",
                        "passwordStrength": "NONE",
                        "samlEnabled": False,
                    },
                    "recordid": "361",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "AUTH_SETTINGS_PROFILE",
                    "time": "2024-11-04 16:30:36.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Other event",
            expected_result=False,
            log={
                "event": {
                    "action": "SIGN_IN",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "LOGIN",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {},
                    "recordid": "354",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "LOGIN",
                    "time": "2024-11-04 16:27:37.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
