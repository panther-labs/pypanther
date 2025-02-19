from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIABackupDeleted(Rule):
    id = "ZIA.Backup.Deleted-prototype"
    default_description = "This rule detects when ZIA backup data was deleted."
    display_name = "ZIA Backup Deleted"
    default_runbook = "Verify that this change was planned. If not, make sure to restore the backup."
    default_reference = "https://help.zscaler.com/zia/about-backup-and-restore"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0005:T1562.008"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        if action == "DELETE" and category == "BACKUP_AND_RESTORE":
            return True
        return False

    def title(self, event):
        return f"[Zscaler.ZIA]: Backup was deleted by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Backup deleted",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@test.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "BACKUP_AND_RESTORE",
                    "clientip": "1.2.3.4",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "adminLogin": "admin@test.zscalerbeta.net",
                        "goldenRestorePoint": False,
                        "id": 163372,
                        "name": "test-restore-2",
                        "time": 1730737925000,
                    },
                    "recordid": "366",
                    "resource": "test-restore-2",
                    "result": "SUCCESS",
                    "subcategory": "BACKUP_AND_RESTORE",
                    "time": "2024-11-04 16:32:18.000000000",
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
