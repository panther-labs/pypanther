from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.zscaler import zia_alert_context, zia_success


@panther_managed
class ZIAAccountAccessRemoved(Rule):
    id = "ZIA.Account.Access.Removed-prototype"
    default_description = "This rule detects when admin user/role was deleted."
    display_name = "ZIA Account Access Removed"
    default_runbook = (
        "Verify that this change was planned. If not, revert the change and ensure this doesn't happen again."
    )
    default_reference = "https://help.zscaler.com/zia/authentication-administration/administrator-role-management"
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0040:T1531"]}
    log_types = [LogType.ZSCALER_ZIA_ADMIN_AUDIT_LOG]
    SENSITIVE_CATEGORIES = ["ADMINISTRATOR_MANAGEMENT", "ROLE_MANAGEMENT"]

    def rule(self, event):
        if not zia_success(event):
            return False
        event_data = event.get("event", {})
        return (
            event_data.get("action", "ACTION_NOT_FOUND") == "DELETE"
            and event_data.get("category", "CATEGORY_NOT_FOUND") in self.SENSITIVE_CATEGORIES
        )

    def title(self, event):
        return f"[Zscaler.ZIA]: Admin account was deleted by admin with id [{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"

    def alert_context(self, event):
        return zia_alert_context(event)

    tests = [
        RuleTest(
            name="Administration > User Management > Add User, remove from Service Admin group",
            expected_result=False,
            log={
                "event": {
                    "action": "UPDATE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "USER_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {
                        "adminUser": False,
                        "department": {
                            "id": 19752838,
                            "isDeleted": False,
                            "isForUnauthenticatedUser": False,
                            "isNonEditable": False,
                            "name": "test",
                        },
                        "email": "johndoe@dev-company.com",
                        "groups": [{"id": 19631231, "isNonEditable": False, "name": "test"}],
                        "id": 19752821,
                        "isNonEditable": False,
                        "miscflags": 0,
                        "name": "johndoe",
                        "systemDefinedGroups": [],
                    },
                    "preaction": {
                        "adminUser": False,
                        "authType": "SAFECHANNEL_DIR",
                        "department": {
                            "id": 16991313,
                            "isDeleted": False,
                            "isForUnauthenticatedUser": False,
                            "isNonEditable": False,
                            "name": "Service Admin",
                        },
                        "email": "johndoe@dev-company.com",
                        "groups": [{"id": 16991312, "isNonEditable": False, "name": "Service Admin"}],
                        "id": 19752821,
                        "miscflags": 268435456,
                        "name": "johndoe",
                    },
                    "recordid": "324",
                    "resource": "johndoe",
                    "result": "SUCCESS",
                    "subcategory": "USER",
                    "time": "2024-10-22 22:01:28.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration Management > Administrators > Edit Administrator, delete administrator",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ADMINISTRATOR_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "adminScope": {"scopeEntities": [], "scopeGroupMemberEntities": [], "type": "ORGANIZATION"},
                        "disabled": False,
                        "email": "johndoe@company.com",
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
                    "recordid": "327",
                    "resource": "johndoe1123",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_ADMIN_USER",
                    "time": "2024-10-22 22:09:01.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration Management > Auditors > Edit Auditor, delete auditor",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ADMINISTRATOR_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "disabled": False,
                        "id": 19752860,
                        "isAuditor": True,
                        "loginName": "arieeel@dev-company.com",
                        "newLocationCreateAllowed": False,
                        "pwdLastModifiedTime": 0,
                        "role": {"deleted": False, "id": 30510, "isNameL10nTag": False, "name": "Auditor"},
                        "userName": "areiiiel",
                    },
                    "recordid": "329",
                    "resource": "areiiiel",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_AUDITOR",
                    "time": "2024-10-22 22:11:56.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration > Role Management > Edit Administrator Role, delete role",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ROLE_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "adminAcctAccess": "READ_WRITE",
                        "alertingAccess": "READ_WRITE",
                        "analysisAccess": "READ_ONLY",
                        "dashboardAccess": "READ_WRITE",
                        "deviceInfoAccess": "READ_ONLY",
                        "id": 32780,
                        "logsLimit": "Unrestricted",
                        "name": "mega admin",
                        "permissions": [
                            "SECURE",
                            "COMPLY",
                            "SSL_POLICY",
                            "ADVANCED_SETTINGS",
                            "FIREWALL_DNS",
                            "NSS_CONFIGURATION",
                            "VZEN_CONFIGURATION",
                            "LOCATIONS",
                            "HOSTED_PAC_FILES",
                            "EZ_AGENT_CONFIGURATIONS",
                            "SECURE_AGENT_NOTIFICATIONS",
                            "VPN_CREDENTIALS",
                            "AUTHENTICATION_SETTINGS",
                            "IDENTITY_PROXY_SETTINGS",
                            "USER_MANAGEMENT",
                            "APIKEY_MANAGEMENT",
                            "PARTNER_INTEGRATION",
                            "POLICY_RESOURCE_MANAGEMENT",
                            "CUSTOM_URL_CAT",
                            "OVERRIDE_EXISTING_CAT",
                            "PROXY_GATEWAY",
                            "TENANT_PROFILE_MANAGEMENT",
                            "STATIC_IPS",
                            "REMOTE_ASSISTANCE_MANAGEMENT",
                            "GRE_TUNNELS",
                            "CLIENT_CONNECTOR_PORTAL",
                            "SUBCLOUDS",
                        ],
                        "policyAccess": "READ_WRITE",
                        "rank": 7,
                        "reportAccess": "READ_WRITE",
                        "reportTimeDuration": -1,
                        "roleType": "EXEC_INSIGHT_AND_ORG_ADMIN",
                        "usernameAccess": "READ_ONLY",
                    },
                    "recordid": "342",
                    "resource": "mega admin",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_ROLE",
                    "time": "2024-10-22 22:31:35.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration > Role Management > Edit SD-WAN Partner API Role, delete role",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ROLE_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "adminAcctAccess": "NONE",
                        "alertingAccess": "READ_ONLY",
                        "analysisAccess": "NONE",
                        "dashboardAccess": "NONE",
                        "deviceInfoAccess": "NONE",
                        "id": 32781,
                        "name": "wanny",
                        "permissions": ["STATIC_IPS", "LOCATIONS", "GRE_TUNNELS", "VPN_CREDENTIALS"],
                        "policyAccess": "READ_WRITE",
                        "rank": 7,
                        "reportAccess": "NONE",
                        "reportTimeDuration": -1,
                        "roleType": "SDWAN",
                        "usernameAccess": "NONE",
                    },
                    "recordid": "345",
                    "resource": "wanny",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_ROLE",
                    "time": "2024-10-22 22:34:58.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
        RuleTest(
            name="Administration > Role Management > Edit API Role, delete role",
            expected_result=True,
            log={
                "event": {
                    "action": "DELETE",
                    "adminid": "admin@16991311.zscalerbeta.net",
                    "auditlogtype": "ZIA",
                    "category": "ROLE_MANAGEMENT",
                    "clientip": "123.123.123.123",
                    "errorcode": "None",
                    "interface": "UI",
                    "postaction": {},
                    "preaction": {
                        "adminAcctAccess": "READ_WRITE",
                        "alertingAccess": "NONE",
                        "analysisAccess": "NONE",
                        "dashboardAccess": "NONE",
                        "deviceInfoAccess": "NONE",
                        "id": 32782,
                        "logsLimit": "Unrestricted",
                        "name": "bad API",
                        "permissions": [
                            "SECURE",
                            "COMPLY",
                            "SSL_POLICY",
                            "ADVANCED_SETTINGS",
                            "FIREWALL_DNS",
                            "LOCATIONS",
                            "VPN_CREDENTIALS",
                            "USER_MANAGEMENT",
                            "POLICY_RESOURCE_MANAGEMENT",
                            "CUSTOM_URL_CAT",
                            "OVERRIDE_EXISTING_CAT",
                            "STATIC_IPS",
                            "GRE_TUNNELS",
                        ],
                        "policyAccess": "READ_WRITE",
                        "rank": 7,
                        "reportAccess": "NONE",
                        "reportTimeDuration": -1,
                        "roleType": "PUBLIC_API",
                        "usernameAccess": "NONE",
                    },
                    "recordid": "346",
                    "resource": "bad API",
                    "result": "SUCCESS",
                    "subcategory": "ADMINISTRATOR_ROLE",
                    "time": "2024-10-22 22:35:06.000000000",
                },
                "sourcetype": "zscalernss-audit",
            },
        ),
    ]
