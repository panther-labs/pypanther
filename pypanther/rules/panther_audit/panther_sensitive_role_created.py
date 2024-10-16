from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type


@panther_managed
class PantherSensitiveRole(Rule):
    id = "Panther.Sensitive.Role-prototype"
    display_name = "A User Role with Sensitive Permissions has been Created"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.HIGH
    tags = ["DataModel", "Persistence:Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_description = "A Panther user role has been created that contains admin level permissions."
    default_runbook = "Contact the creator of this role to ensure its creation was appropriate."
    default_reference = "https://docs.panther.com/system-configuration/rbac"
    summary_attributes = ["p_any_ip_addresses"]
    PANTHER_ADMIN_PERMISSIONS = [
        "UserModify",
        "OrganizationAPITokenModify",
        "OrganizationAPITokenRead",
        "GeneralSettingsModify",
    ]
    PANTHER_ROLE_ACTIONS = [event_type.USER_GROUP_CREATED, event_type.USER_GROUP_MODIFIED]

    def rule(self, event):
        if event.udm("event_type") not in self.PANTHER_ROLE_ACTIONS:
            return False
        permissions = event.deep_get("actionParams", "dynamic", "input", "permissions")
        if permissions is None:
            event.deep_get("actionParams", "input", "permissions", default="")
        role_permissions = set(permissions)
        return (
            len(set(self.PANTHER_ADMIN_PERMISSIONS).intersection(role_permissions)) > 0
            and event.get("actionResult") == "SUCCEEDED"
        )

    def title(self, event):
        role_name = event.deep_get("actionParams", "dynamic", "input", "name")
        if role_name is None:
            role_name = event.deep_get("actionParams", "input", "name", default="<UNKNWON ROLE>")
        return f"Role with Admin Permissions created by {event.udm('actor_user')}Role Name: {role_name}"

    def alert_context(self, event):
        return {
            "user": event.udm("actor_user"),
            "role_name": event.deep_get("actionParams", "name"),
            "ip": event.udm("source_ip"),
        }

    tests = [
        RuleTest(
            name="Admin Role Created",
            expected_result=True,
            log={
                "actionName": "CREATE_USER_ROLE",
                "actionParams": {
                    "dynamic": {
                        "input": {
                            "logTypeAccessKind": "DENY_ALL",
                            "name": "New Admins",
                            "permissions": ["GeneralSettingsModify", "GeneralSettingsRead", "SummaryRead"],
                        },
                    },
                },
                "actionResult": "SUCCEEDED",
                "actor": {
                    "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "1111111"},
                    "id": "11111111",
                    "name": "Homer Simpson",
                    "type": "USER",
                },
                "errors": None,
                "p_log_type": "Panther.Audit",
                "pantherVersion": "1.2.3",
                "sourceIP": "1.2.3.4",
                "timestamp": "2022-04-27 20:47:09.425",
            },
        ),
        RuleTest(
            name="Non-Admin Role Created",
            expected_result=False,
            log={
                "actionName": "CREATE_USER_ROLE",
                "actionParams": {
                    "dynamic": {
                        "input": {
                            "logTypeAccessKind": "DENY_ALL",
                            "name": "New Admins",
                            "permissions": ["SummaryRead"],
                        },
                    },
                },
                "actionResult": "SUCCEEDED",
                "actor": {
                    "attributes": {"email": "homer@springfield.gov", "emailVerified": True, "roleId": "1111111"},
                    "id": "11111111",
                    "name": "Homer Simpson",
                    "type": "USER",
                },
                "errors": None,
                "p_log_type": "Panther.Audit",
                "pantherVersion": "1.2.3",
                "sourceIP": "1.2.3.4",
                "timestamp": "2022-04-27 20:47:09.425",
            },
        ),
        RuleTest(
            name="nonetype error",
            expected_result=False,
            log={
                "XForwardedFor": ["1.2.3.4", "5.6.7.8"],
                "actionDescription": "Adds a new User role to Panther",
                "actionName": "CREATE_USER_ROLE",
                "actionParams": {
                    "dynamic": {
                        "input": {
                            "logTypeAccess": ["Okta.SystemLog"],
                            "logTypeAccessKind": "ALLOW",
                            "name": "ITE Role",
                            "permissions": ["AlertRead", "DataAnalyticsRead"],
                        },
                    },
                    "static": {},
                },
                "actionResult": "FAILED",
                "actor": {
                    "attributes": {
                        "email": "random@noreply.com",
                        "emailVerified": False,
                        "roleId": "2a7bfe22-666d-4f71-99d2-c16b8666eca1",
                        "roleName": "Admin",
                    },
                    "id": "PantherSSO_random@noreply.com",
                    "name": "random@noreply.com",
                    "type": "USER",
                },
                "errors": [
                    {
                        "message": "You cannot save a role that has both log type restrictions and alerts/detections permissions at this time.",
                    },
                ],
                "p_alert_creation_time": "2023-02-09 21:47:09.745566000",
                "p_alert_id": "7eb5ca596b2153f95885cb2440e12345",
                "p_alert_severity": "HIGH",
                "p_alert_update_time": "2023-02-09 21:47:09.745566000",
                "p_any_ip_addresses": ["1.2.3.4", "5.6.7.8"],
                "p_any_trace_ids": ["PantherSSO_random@noreply.com"],
                "p_any_usernames": ["random@noreply.com"],
                "p_enrichment": {
                    "ipinfo_asn": {
                        "sourceIP": {
                            "asn": "AS396982",
                            "domain": "google.com",
                            "name": "Google LLC",
                            "route": "208.127.224.0/21",
                            "type": "hosting",
                        },
                    },
                    "ipinfo_location": {
                        "sourceIP": {
                            "city": "Ashburn",
                            "country": "US",
                            "lat": "39.04372",
                            "lng": "-77.48749",
                            "postal_code": "20147",
                            "region": "Virginia",
                            "region_code": "VA",
                            "timezone": "America/New_York",
                        },
                    },
                },
                "p_event_time": "2023-02-09 21:45:59.352910070",
                "p_log_type": "Panther.Audit",
                "p_parse_time": "2023-02-09 21:46:53.858602089",
                "p_row_id": "b29dff36ad73cb77a5d7a3a816c39c2a",
                "p_rule_error": '\'NoneType\' object is not iterable: Panther.Sensitive.Role.py, line 20, in rule    role_permissions = set(event.deep_get("actionParams", "input", "permissions"))',
                "p_rule_id": "Panther.Sensitive.Role",
                "p_rule_reports": {"MITRE ATT&CK": ["TA0003:T1098"]},
                "p_rule_severity": "HIGH",
                "p_rule_tags": ["DataModel", "Persistence:Account Manipulation"],
                "p_schema_version": 0,
                "p_source_id": "9a116557-0a1c-4a21-8565-1135dfe5e82b",
                "p_source_label": "panther-audit-logs-us-east-1",
                "pantherVersion": "1.53.7",
                "sourceIP": "1.2.3.4",
                "timestamp": "2023-02-09 21:45:59.352910070",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
            },
        ),
    ]
