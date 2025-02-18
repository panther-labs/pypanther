from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIACloudAccountCreated(Rule):
    id = "ZIA.Cloud.Account.Created-prototype"
    default_description = "This rule detects when new cloud account was created."
    display_name = "ZIA Cloud Account Created"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://help.zscaler.com/zia/choosing-provisioning-and-authentication-methods"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0003:T1136.003"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]

    def rule(self, event):
        if not zia_success(event):
            return False
        action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
        category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
        role_name = event.deep_get("event", "postaction", "role", "name", default="<ROLE_NAME_NOT_FOUND>").lower()
        if (
            action == "CREATE"
            and category == "ADMINISTRATOR_MANAGEMENT"
            and ("admin" in role_name or "audit" in role_name)
        ):
            return True
        return False

    def title(self, event):
        return f"[Zscaler.ZIA]: New admin role was created by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Administration > User Management > Add User, Service Admin group",
            expected_result=False,
            log={
                "event": {
                    "action": "CREATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "USER_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "department": {
                            "id": 16991313,
                            "isDeleted": False,
                            "isForUnauthenticatedUser": False,
                            "isNonEditable": True,
                            "name": "Service Admin",
                        },
                        "email": "johndoe@dev-company.com",
                        "groups": [{"id": 16991312, "isNonEditable": True, "name": "Service Admin"}],
                        "id": 19752821,
                        "miscflags": 0,
                        "name": "johndoe",
                        "password": "*****",
                        "systemDefinedGroups": [],
                    },
                    "preaction": {
                        "department": {
                            "id": 16991313,
                            "isDeleted": False,
                            "isForUnauthenticatedUser": False,
                            "isNonEditable": True,
                            "name": "Service Admin",
                        },
                        "email": "johndoe@dev-company.com",
                        "groups": [{"id": 16991312, "isNonEditable": True, "name": "Service Admin"}],
                        "id": 19752821,
                        "miscflags": 0,
                        "name": "johndoe",
                        "password": "*****",
                        "systemDefinedGroups": [],
                    },
                    "recordid": "321",
                    "resource": "johndoe",
                    "result": "SUCCESS",
                    "subcategory": "USER",
                    "time": "2024-10-22 21:57:58.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration Management > Administrators > Add Administrator",
            expected_result=True,
            log={
                "event": {
                    "action": "CREATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ADMINISTRATOR_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "adminScope": {"scopeEntities": [], "scopeGroupMemberEntities": [], "type": "ORGANIZATION"},
                        "disabled": False,
                        "email": "ajohndoe@company.com",
                        "id": 19752821,
                        "isExecMobileAppEnabled": True,
                        "isPasswordLoginAllowed": True,
                        "loginName": "johndoe@dev-company.com",
                        "pwdLastModifiedTime": 1729634767,
                        "role": {
                            "deleted": False,
                            "extensions": {"adminRank": "0", "roleType": "EXEC_INSIGHT_AND_ORG_ADMIN"},
                            "id": 24354,
                            "isNameL10nTag": True,
                            "name": "Super Admin",
                        },
                        "userName": "johndoe1123",
                    },
                    "preaction": {
                        "adminScope": {"scopeEntities": [], "scopeGroupMemberEntities": [], "type": "ORGANIZATION"},
                        "disabled": False,
                        "email": "johndoe@company.com",
                        "id": 0,
                        "isAuditor": False,
                        "isDefaultAdmin": False,
                        "isExecMobileAppEnabled": True,
                        "isPasswordExpired": False,
                        "isPasswordLoginAllowed": True,
                        "loginName": "johndoe@dev-company.com",
                        "newLocationCreateAllowed": False,
                        "password": "*****",
                        "pwdLastModifiedTime": 0,
                        "role": {"deleted": False, "id": 24354, "isNameL10nTag": False, "name": "Super Admin"},
                        "userName": "johndoe1123",
                    },
                    "recordid": "326",
                    "resource": "johndoe1123",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_ADMIN_USER",
                    "time": "2024-10-22 22:06:04.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration Management  > Auditors > Add Auditor",
            expected_result=True,
            log={
                "event": {
                    "action": "CREATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ADMINISTRATOR_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "disabled": False,
                        "id": 19752860,
                        "isAuditor": True,
                        "loginName": "arieeel@dev-company.com",
                        "newLocationCreateAllowed": False,
                        "pwdLastModifiedTime": 0,
                        "role": {"deleted": False, "id": 30510, "isNameL10nTag": False, "name": "Auditor"},
                        "userName": "areiiiel",
                    },
                    "preaction": {
                        "adminScope": {"scopeEntities": [], "scopeGroupMemberEntities": [], "type": "ORGANIZATION"},
                        "disabled": False,
                        "id": 0,
                        "isAuditor": True,
                        "loginName": "arieeel@dev-company.com",
                        "newLocationCreateAllowed": False,
                        "password": "*****",
                        "pwdLastModifiedTime": 0,
                        "userName": "areiiiel",
                    },
                    "recordid": "328",
                    "resource": "areiiiel",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_AUDITOR",
                    "time": "2024-10-22 22:10:28.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
