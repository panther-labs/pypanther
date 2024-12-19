from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIAGoldenRestorePointDropped(Rule):
    id = "ZIA.Golden.Restore.Point.Dropped-prototype"
    default_description = "This rule detects when ZIA goldenRestorePoint was dropped. It means that some piece of information that was impossible to delete before, now is deletable"
    display_name = "ZIA Golden Restore Point Dropped"
    default_runbook = "Verify that this change was planned. If not, revert the change."
    default_reference = "https://help.zscaler.com/zia/about-backup-and-restore"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        golden_restore_point_pre = event.deep_get(
            "event",
            "preaction",
            "goldenRestorePoint",
            default="<PRE_RESTORE_POINT_NOT_FOUND>",
        )
        golden_restore_point_post = event.deep_get(
            "event",
            "postaction",
            "goldenRestorePoint",
            default="<POPT_RESTORE_POINT_NOT_FOUND>",
        )
        if (
            action == "UPDATE"
            and category == "BACKUP_AND_RESTORE"
            and (golden_restore_point_pre is True)
            and (golden_restore_point_post is False)
        ):
            return True
        return False

    def title(self, event):
        return f"[Zscaler.ZIA]: goldenRestorePoint was dropped by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="goldenRestorePoint dropped",
            expected_result=True,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "BACKUP_AND_RESTORE",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "adminLogin": "admin@test.zscalerbeta.net",
                        "goldenRestorePoint": False,
                        "id": 163371,
                        "name": "test-restore",
                        "time": 1730737915000,
                    },
                    "preaction": {
                        "adminLogin": "admin@test.zscalerbeta.net",
                        "goldenRestorePoint": True,
                        "id": 163371,
                        "name": "test-restore",
                        "time": 1730737915000,
                    },
                    "recordid": "367",
                    "resource": "test-restore",
                    "result": "SUCCESS",
                    "subcategory": "BACKUP_AND_RESTORE",
                    "time": "2024-11-04 16:32:28.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Backup created",
            expected_result=False,
            log={
                "event": {
                    "action": "CREATE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "BACKUP_AND_RESTORE",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "adminLogin": "admin@test.zscalerbeta.net",
                        "goldenRestorePoint": False,
                        "id": 163372,
                        "name": "test-restore-2",
                        "time": 1730737925000,
                    },
                    "preaction": {"goldenRestorePoint": False, "id": 0, "name": "test-restore-2", "time": 0},
                    "recordid": "365",
                    "resource": "test-restore-2",
                    "result": "SUCCESS",
                    "subcategory": "BACKUP_AND_RESTORE",
                    "time": "2024-11-04 16:32:05.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
