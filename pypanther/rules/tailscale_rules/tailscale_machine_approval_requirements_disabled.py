from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get
from pypanther.helpers.panther_tailscale_helpers import is_tailscale_admin_console_event, tailscale_alert_context

tailscale_machine_approval_requirements_disabled_tests: list[RuleTest] = [
    RuleTest(
        name="Machine Approval Requirements Disabled",
        expected_result=True,
        log={
            "event": {
                "action": "DISABLE",
                "actor": {
                    "displayName": "Homer Simpson",
                    "id": "uhfQwM4CNTRL",
                    "loginName": "homer.simpson@yourcompany.io",
                    "type": "USER",
                },
                "eventGroupID": "6dae044c7a8998599e94657b511d28f9",
                "origin": "ADMIN_CONSOLE",
                "target": {
                    "id": "panther.com",
                    "name": "panther.com",
                    "property": "MACHINE_APPROVAL_NEEDED",
                    "type": "TAILNET",
                },
            },
            "fields": {"recorded": "2023-06-27 22:58:15.824694387"},
            "p_any_emails": ["homer.simpson@yourcompany.io"],
            "p_any_md5_hashes": ["6dae044c7a8998599e94657b511d28f9"],
            "p_any_usernames": ["homersimpson"],
            "p_event_time": "2023-06-27 23:02:08.54",
            "p_log_type": "Custom.TailscaleAudit",
            "p_parse_time": "2023-06-27 23:02:08.54",
            "p_row_id": "8ec49771e630f6e8e5fdb28319d95c",
            "p_schema_version": 4,
            "p_source_id": "3acfbe1d-f7b2-4c3f-a26e-8da418fd29ef",
            "p_source_label": "Custom Tailscale Audit",
            "p_timeline": "2023-06-27 23:02:08.54",
            "p_udm": {},
            "time": 1687906694.915,
        },
    ),
    RuleTest(
        name="Other Event",
        expected_result=False,
        log={
            "event": {
                "action": "CREATE",
                "actor": {
                    "displayName": "Homer Simpson",
                    "id": "uodc9f3CNTRL",
                    "loginName": "homer.simpson@yourcompany.io",
                    "type": "USER",
                },
                "eventGroupID": "9f880e02981e341447958344b7b4071f",
                "new": {},
                "origin": "ADMIN_CONSOLE",
                "target": {"id": "k6r3fm3CNTRL", "name": "API key", "type": "API_KEY"},
            },
            "fields": {"recorded": "2023-07-19 16:11:41.778839718"},
            "p_any_actor_ids": ["uodc9f3CNTRL"],
            "p_any_emails": ["homer.simpson@yourcompany.io"],
            "p_any_usernames": ["homersimpson"],
            "p_event_time": "2023-07-19 16:11:41.601000",
            "p_log_type": "Tailscale.Audit",
            "p_parse_time": "2023-07-19 16:14:56.865276",
            "p_row_id": "02eaf97ec9caaaabff8882ba19ad1d",
            "p_schema_version": 0,
            "p_source_id": "5d65e24a-7ebb-403b-803c-51396e03d201",
            "p_source_label": "Tailscale Audit and Network Logs",
            "p_udm": {},
            "time": "2023-07-19 16:11:41.601000000",
        },
    ),
]


@panther_managed
class TailscaleMachineApprovalRequirementsDisabled(Rule):
    default_description = "A Tailscale User disabled machine approval requirement settings in your organization's tenant. This means devices can access your network without requiring approval."
    display_name = "Tailscale Machine Approval Requirements Disabled"
    default_runbook = "Assess if this was done by the user for a valid business reason. Be vigilant to re-enable this setting as it's in the best security interest for your organization's security posture."
    default_reference = "https://tailscale.com/kb/1099/device-approval/"
    default_severity = Severity.HIGH
    log_types = [LogType.TAILSCALE_AUDIT]
    id = "Tailscale.Machine.Approval.Requirements.Disabled-prototype"
    tests = tailscale_machine_approval_requirements_disabled_tests

    def rule(self, event):
        action = deep_get(event, "event", "action", default="<NO_ACTION_FOUND>")
        target_property = deep_get(event, "event", "target", "property", default="<NO_TARGET_PROPERTY_FOUND>")
        return all(
            [
                action == "DISABLE",
                target_property == "MACHINE_APPROVAL_NEEDED",
                is_tailscale_admin_console_event(event),
            ],
        )

    def title(self, event):
        user = deep_get(event, "event", "actor", "loginName", default="<NO_USER_FOUND>")
        return f"Tailscale user [{user}] disabled device approval requirements for new devices accessing your organization’s network."

    def alert_context(self, event):
        return tailscale_alert_context(event)
