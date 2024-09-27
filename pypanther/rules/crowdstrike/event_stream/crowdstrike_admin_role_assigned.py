from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.crowdstrike_event_streams import audit_keys_dict, cs_alert_context


@panther_managed
class CrowdstrikeAdminRoleAssigned(Rule):
    id = "Crowdstrike.AdminRoleAssigned-prototype"
    display_name = "Crowdstrike Admin Role Assigned"
    log_types = [LogType.CROWDSTRIKE_EVENT_STREAMS]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0003:T1098.003", "TA0004:T1098.003"]}
    default_description = "A user was assigned a priviledged role"
    default_runbook = "Confirm the role assignment is justified."
    # List of priviledged roles.
    # IMPORTANT: YOU MUST ADD ANY CUSTOM ADMIN ROLES YOURSELF
    # NG SIEM Admin
    # Remote Responder Admin
    ADMIN_ROLES = {
        "billing_dashboard_admin",
        "falconhost_admin",
        "firewall_manager",
        "xdr_admin",
        "remote_responder_three",
    }

    def get_roles_assigned(self, event):
        """Returns a list of the roles assigned in this event."""
        # Extract the AuditKeyValues construct
        audit_keys = audit_keys_dict(event)
        # Return Roles
        return audit_keys.get("roles", "").split(",")

    def rule(self, event):
        # Ignore non role-granting events
        if not all([event.deep_get("event", "OperationName") == "grantUserRoles", event.deep_get("event", "Success")]):
            return False
        # Raise alert if any of the admin roles were assigned
        roles_assigned = self.get_roles_assigned(event)
        return bool(self.ADMIN_ROLES & set(roles_assigned))

    def title(self, event):
        audit_keys = audit_keys_dict(event)
        actor = audit_keys["actor_user"]
        target = audit_keys["target_name"]
        admin_roles = set(self.get_roles_assigned(event)) & self.ADMIN_ROLES
        return f"{actor} assigned admin roles to {target}: {', '.join(list(admin_roles))}"

    def dedup(self, event):
        # The title includes the role names, but if the actor assigned more roles to the user, we
        #   dedup those alerts as well.
        audit_keys = audit_keys_dict(event)
        actor = audit_keys["actor_user"]
        target = audit_keys["target_name"]
        return f"{actor}-{target}"

    def alert_context(self, event):
        context = cs_alert_context(event)
        actor = context.get("actor_user", "UNKNWON_ACTOR")
        target = context.get("target_name", "UNKNOWN_TARGET")
        context["actor_target"] = f"{actor}-{target}"
        return context

    tests = [
        RuleTest(
            name="Admin Role Assigned (Single)",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_name", "ValueString": "merry.brandybuck@hobbiton.co"},
                        {"Key": "target_user_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {"Key": "roles", "ValueString": "billing_dashboard_admin"},
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "897d300ad09137b362ee6a62846a9277"},
                        {"Key": "actor_user", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "actor_user_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                    ],
                    "OperationName": "grantUserRoles",
                    "ServiceName": "Crowdstrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 21:32:49.000000000",
                    "UserId": "peregrin.took@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 21:32:49.531000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 342905,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Admin Role Assigned (Multiple)",
            expected_result=True,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_name", "ValueString": "merry.brandybuck@hobbiton.co"},
                        {"Key": "target_user_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {
                            "Key": "roles",
                            "ValueString": "custom_non_admin_role,billing_dashboard_admin,falconhost_admin",
                        },
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "897d300ad09137b362ee6a62846a9277"},
                        {"Key": "actor_user", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "actor_user_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                    ],
                    "OperationName": "grantUserRoles",
                    "ServiceName": "Crowdstrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 21:32:49.000000000",
                    "UserId": "peregrin.took@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 21:32:49.531000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 342905,
                    "version": "1.0",
                },
            },
        ),
        RuleTest(
            name="Non-Admin Role Assigned",
            expected_result=False,
            log={
                "event": {
                    "AuditKeyValues": [
                        {"Key": "target_name", "ValueString": "merry.brandybuck@hobbiton.co"},
                        {"Key": "target_user_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                        {"Key": "target_cid", "ValueString": "fake_customer_id"},
                        {"Key": "roles", "ValueString": "custom_non_admin_role"},
                        {"Key": "actor_cid", "ValueString": "fake_customer_id"},
                        {"Key": "trace_id", "ValueString": "897d300ad09137b362ee6a62846a9277"},
                        {"Key": "actor_user", "ValueString": "peregrin.took@hobbiton.co"},
                        {"Key": "actor_user_uuid", "ValueString": "e70e5306-4a83-4a9f-9b59-a78c304c438b"},
                    ],
                    "OperationName": "grantUserRoles",
                    "ServiceName": "Crowdstrike Authentication",
                    "Success": True,
                    "UTCTimestamp": "2024-07-22 21:32:49.000000000",
                    "UserId": "peregrin.took@hobbiton.co",
                    "UserIp": "1.1.1.1",
                },
                "metadata": {
                    "customerIDString": "fake_customer_id",
                    "eventCreationTime": "2024-07-22 21:32:49.531000000",
                    "eventType": "AuthActivityAuditEvent",
                    "offset": 342905,
                    "version": "1.0",
                },
            },
        ),
    ]
