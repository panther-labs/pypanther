from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.duo import deserialize_administrator_log_event_description, duo_alert_context


@panther_managed
class DuoAdminNewAdminAPIAppIntegration(Rule):
    default_description = "Identifies creation of new Admin API integrations for Duo."
    display_name = "Duo Admin New Admin API App Integration"
    default_reference = "https://duo.com/docs/adminapi#overview"
    default_severity = Severity.HIGH
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.New.Admin.API.App.Integration-prototype"

    def rule(self, event):
        if event.get("action") == "integration_create":
            description = deserialize_administrator_log_event_description(event)
            integration_type = description.get("type")
            return integration_type == "Admin API"
        return False

    def title(self, event):
        return f"Duo: [{event.get('username', '<username_not_found>')}] created a new Admin API integration to [{event.get('object', '<object_not_found>')}]"

    def alert_context(self, event):
        return duo_alert_context(event)

    tests = [
        RuleTest(
            name="Admin API Integration Created",
            expected_result=True,
            log={
                "action": "integration_create",
                "description": '{"greeting": "", "notes": "", "offline_auth_enabled": 0, "offline_max_days": 0, "offline_max_attempts": 0, "type": "Admin API", "raw_type": "adminapi", "name": "Admin API", "self_service_allowed": false, "username_normalization_policy": "None", "missing_web_referer_policy": "deny", "networks_for_api_access": "", "group_access": ""}',
                "isotimestamp": "2021-11-30 17:15:33",
                "object": "Admin API",
                "timestamp": "2021-11-30 17:15:33",
                "username": "Homer Simpson",
            },
        ),
        RuleTest(
            name="Non Admin API Integration",
            expected_result=False,
            log={
                "action": "integration_create",
                "description": '{"greeting": "", "notes": "", "offline_auth_enabled": 0, "offline_max_days": 0, "offline_max_attempts": 0, "type": "1Password", "raw_type": "1password", "name": "1Password", "self_service_allowed": false, "username_normalization_policy": "None", "missing_web_referer_policy": "deny", "networks_for_api_access": "", "group_access": ""}',
                "isotimestamp": "2021-11-30 17:11:51",
                "object": "1Password",
                "timestamp": "2021-11-30 17:11:51",
                "username": "Homer Simpson",
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "action": "user_update",
                "description": '{"phones": ""}',
                "isotimestamp": "2021-07-02 18:31:56",
                "object": "homer.simpson@simpsons.io",
                "timestamp": "2021-07-02 18:31:56",
                "username": "Homer Simpson",
            },
        ),
    ]
