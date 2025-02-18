from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIALogsDownloaded(Rule):
    id = "ZIA.Logs.Downloaded-prototype"
    default_description = "This rule detects when ZIA Audit Logs were downloaded."
    display_name = "ZIA Logs Downloaded"
    default_runbook = "Verify that this change was planned. If not, make sure no sensitive information was leaked."
    default_reference = "https://help.zscaler.com/zia/about-audit-logs"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0007:T1654"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        if action == "DOWNLOAD" and category == "AUDIT_LOGS":
            return True
        return False

    def title(self, event):
        return f"[Zscaler.ZIA]: Audit logs were downloaded by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Logs downloaded",
            expected_result=True,
            log={
                "event": {
                    "action": "DOWNLOAD",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "AUDIT_LOGS",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {},
                    "recordid": "363",
                    "resource": "None",
                    "result": "SUCCESS",
                    "subcategory": "AUDIT_LOGS",
                    "time": "2024-11-04 16:31:24.000000000",
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
