from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type


@panther_managed
class PantherUserModified(Rule):
    id = "Panther.User.Modified-prototype"
    display_name = "A User's Panther Account was Modified"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.HIGH
    tags = ["DataModel", "Persistence:Account Manipulation"]
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_description = (
        "A Panther user's role has been modified. This could mean password, email, or role has changed for the user."
    )
    default_runbook = "Validate that this user modification was intentional."
    default_reference = "https://docs.panther.com/panther-developer-workflows/api/operations/user-management"
    summary_attributes = ["p_any_ip_addresses"]
    PANTHER_USER_ACTIONS = [event_type.USER_ACCOUNT_MODIFIED]

    def rule(self, event):
        if event.udm("event_type") not in self.PANTHER_USER_ACTIONS:
            return False
        return event.get("actionResult") == "SUCCEEDED"

    def title(self, event):
        change_target = event.deep_get("actionParams", "dynamic", "input", "email")
        if change_target is None:
            change_target = event.deep_get("actionParams", "input", "email")
        if change_target is None:
            change_target = event.deep_get("actionParams", "email", default="<UNKNOWN_USER>")
        return f"The user account {change_target} was modified by {event.udm('actor_user')}"

    def alert_context(self, event):
        change_target = event.deep_get("actionParams", "dynamic", "input", "email")
        if change_target is None:
            change_target = event.deep_get("actionParams", "input", "email", default="<UNKNOWN_USER>")
        return {"user": event.udm("actor_user"), "change_target": change_target, "ip": event.udm("source_ip")}

    def severity(self, event):
        user = event.udm("actor_user")
        if user == "scim":
            return "INFO"
        if event.deep_get("actor", "id") == "00000000-0000-4000-8000-000000000000":
            return "INFO"
        return "DEFAULT"

    tests = [
        RuleTest(
            name="Admin Role Created",
            expected_result=False,
            log={
                "actionName": "CREATE_USER_ROLE",
                "actionParams": {
                    "input": {
                        "logTypeAccessKind": "DENY_ALL",
                        "name": "New Admins",
                        "permissions": ["GeneralSettingsModify", "GeneralSettingsRead", "SummaryRead"],
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
            name="Users's email was changed",
            expected_result=True,
            log={
                "XForwardedFor": ["1.2.3.4", "5.6.7.8"],
                "actionDescription": "Updates the information for a user",
                "actionName": "UPDATE_USER",
                "actionParams": {
                    "dynamic": {
                        "input": {
                            "email": "user-email+anyplus@springfield.gov",
                            "familyName": "Email",
                            "givenName": "User",
                            "id": "75757575-7575-7575-7575-757575757575",
                            "role": {"kind": "ID", "value": "(redacted)"},
                        },
                    },
                    "static": {},
                },
                "actionResult": "SUCCEEDED",
                "actor": {
                    "attributes": {
                        "email": "admin.email@springfield.gov",
                        "emailVerified": False,
                        "roleId": "89898989-8989-8989-8989-898989898989",
                        "roleName": "Admin",
                    },
                    "id": "PantherSSO_admin.email@springfield.gov",
                    "name": "admin.email@springfield.gov",
                    "type": "USER",
                },
                "p_any_ip_addresses": ["5.6.7.8", "1.2.3.4"],
                "p_any_trace_ids": ["PantherSSO_admin.email@springfield.gov"],
                "p_any_usernames": ["admin.email@springfield.gov"],
                "p_event_time": "2022-11-08 19:23:04.841",
                "p_log_type": "Panther.Audit",
                "p_parse_time": "2022-11-08 19:23:47.278",
                "p_row_id": "12341234123412341234123412341234",
                "p_source_id": "34343434-3434-3434-3434-343434343434",
                "p_source_label": "panther-audit-logs-region-name",
                "pantherVersion": "1.2.3",
                "sourceIP": "1.2.3.4",
                "timestamp": "2022-11-08 19:23:04.841",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
            },
        ),
        RuleTest(
            name="Users's role was changed",
            expected_result=True,
            log={
                "XForwardedFor": ["5.6.7.8", "1.2.3.4"],
                "actionDescription": "Updates the information for a user",
                "actionName": "UPDATE_USER",
                "actionParams": {
                    "dynamic": {
                        "input": {
                            "email": "user.email@springfield.gov",
                            "familyName": "Email",
                            "givenName": "User",
                            "id": "PantherSSO_user.email@springfield.gov",
                            "role": {"kind": "ID", "value": "(redacted)"},
                        },
                    },
                    "static": {},
                },
                "actionResult": "SUCCEEDED",
                "actor": {
                    "attributes": {
                        "email": "admin.email@springfield.gov",
                        "emailVerified": False,
                        "roleId": "12341234-1234-1234-1234-123412341234",
                        "roleName": "Admin",
                    },
                    "id": "PantherSSO_admin.email@springfield.gov",
                    "name": "admin.email@springfield.gov",
                    "type": "USER",
                },
                "p_any_ip_addresses": ["5.6.7.8", "1.2.3.4"],
                "p_any_trace_ids": ["PantherSSO_admin.email@springfield.gov"],
                "p_any_usernames": ["admin.email@springfield.gov"],
                "p_event_time": "2022-11-09 23:10:35.504",
                "p_log_type": "Panther.Audit",
                "p_parse_time": "2022-11-09 23:11:47.112",
                "p_row_id": "56785678567856785678567856785678",
                "p_source_id": "34563456-3456-3456-3456-345634563456",
                "p_source_label": "panther-audit-logs-region-name",
                "pantherVersion": "1.2.3",
                "sourceIP": "5.6.7.8",
                "timestamp": "2022-11-09 23:10:35.504",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
            },
        ),
        RuleTest(
            name="SCIM based user provision - INFO level",
            expected_result=True,
            log={
                "actionDescription": "User updated via SCIM",
                "actionName": "UPDATE_USER",
                "actionParams": {
                    "input": {
                        "email": "user.email@springfield.gov",
                        "familyName": "",
                        "givenName": "",
                        "id": "PantherSSO_user.email@springfield.gov",
                        "requesterId": "00000000-0000-4000-8000-000000000000",
                        "roleId": None,
                    },
                },
                "actionResult": "SUCCEEDED",
                "actor": {"id": "scim", "name": "scim", "type": "TOKEN"},
                "p_any_actor_ids": ["scim"],
                "p_any_usernames": ["scim"],
                "p_event_time": "2023-06-23 17:49:37.553847671",
                "p_log_type": "Panther.Audit",
                "p_parse_time": "2023-06-23 17:50:46.933652106",
                "p_source_label": "panther audit logs",
                "sourceIP": "12.12.12.12",
                "timestamp": "2023-06-23 17:49:37.553847671",
            },
        ),
        RuleTest(
            name="User modified by System account",
            expected_result=True,
            log={
                "actionDescription": "User updated automatically by SAML.",
                "actionName": "UPDATE_USER",
                "actionParams": {
                    "dynamic": {
                        "input": {
                            "email": "john.doe@usgs.gov",
                            "familyName": "Doe",
                            "givenName": "John",
                            "role": "AnalystReadOnly",
                        },
                    },
                },
                "actionResult": "SUCCEEDED",
                "actor": {"id": "00000000-0000-4000-8000-000000000000", "name": "System", "type": "USER"},
                "p_log_type": "Panther.Audit",
                "pantherVersion": "1.86.15",
                "sourceIP": "",
                "timestamp": "2023-10-25 05:30:15.618835297",
            },
        ),
    ]
