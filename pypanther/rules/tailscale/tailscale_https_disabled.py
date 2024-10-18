from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.tailscale import is_tailscale_admin_console_event, tailscale_alert_context


@panther_managed
class TailscaleHTTPSDisabled(Rule):
    default_description = "A Tailscale User disabled HTTPS settings in your organization's tenant."
    display_name = "Tailscale HTTPS Disabled"
    default_runbook = "Assess if this was done by the user for a valid business reason. Be vigilant to re-enable this setting as it's in the best security interest for your organization's security posture."
    default_reference = "https://tailscale.com/kb/1153/enabling-https/#disable-https"
    default_severity = Severity.HIGH
    log_types = [LogType.TAILSCALE_AUDIT]
    id = "Tailscale.HTTPS.Disabled-prototype"

    def rule(self, event):
        action = event.deep_get("event", "action", default="<NO_ACTION_FOUND>")
        target_property = event.deep_get("event", "target", "property", default="<NO_TARGET_PROPERTY_FOUND>")
        return all([action == "DISABLE", target_property == "HTTPS", is_tailscale_admin_console_event(event)])

    def title(self, event):
        user = event.deep_get("event", "actor", "loginName", default="<NO_USER_FOUND>")
        target_id = event.deep_get("event", "target", "id", default="<NO_TARGET_ID_FOUND>")
        return f"Tailscale user [{user}] disabled HTTPS for [{target_id}] in your organization’s tenant."

    def alert_context(self, event):
        return tailscale_alert_context(event)

    tests = [
        RuleTest(
            name="HTTPS Disabled",
            expected_result=True,
            log={
                "event": {
                    "action": "DISABLE",
                    "actor": {
                        "displayName": "Homer Simpson",
                        "id": "uodc9f3CNTRL",
                        "loginName": "homer.simpson@yourcompany.io",
                        "type": "USER",
                    },
                    "eventGroupID": "1770eb26fb58fbf67fd8fbfcc2056e66",
                    "origin": "ADMIN_CONSOLE",
                    "target": {"id": "yoururl.com", "name": "yoururl.com", "property": "HTTPS", "type": "TAILNET"},
                },
                "fields": {"recorded": "2023-07-19 16:10:48.385283827"},
                "p_any_actor_ids": ["uodc9f3CNTRL"],
                "p_any_emails": ["homer.simpson@yourcompany.io"],
                "p_any_usernames": ["andrea.youwakim"],
                "p_event_time": "2023-07-19 16:10:48.172000",
                "p_log_type": "Tailscale.Audit",
                "p_parse_time": "2023-07-19 16:13:56.849092",
                "p_row_id": "5e197fb53834e39eeab7feb9198d04",
                "p_schema_version": 0,
                "p_source_id": "5d65e24a-7ebb-403b-803c-51396e03d201",
                "p_source_label": "Tailscale Audit and Network Logs",
                "p_udm": {},
                "time": "2023-07-19 16:10:48.172000000",
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
