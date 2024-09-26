from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.duo import duo_alert_context


@panther_managed
class DuoAdminPolicyUpdated(Rule):
    default_description = "A Duo Administrator updated a Policy, which governs how users authenticate."
    display_name = "Duo Admin Policy Updated"
    default_reference = "https://duo.com/docs/policy#authenticators-policy-settings"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DUO_ADMINISTRATOR]
    id = "Duo.Admin.Policy.Updated-prototype"

    def rule(self, event):
        return event.get("action") == "policy_update"

    def title(self, event):
        return f"Duo: [{event.get('username', '<username_not_found>')}] updated [{event.get('object', 'Duo Policy')}]."

    def alert_context(self, event):
        return duo_alert_context(event)

    tests = [
        RuleTest(
            name="Policy Update",
            expected_result=True,
            log={
                "action": "policy_update",
                "description": '{"adaptive_auth_display_unit": "days", "trusted_mobile_endpoint_policy": "no action", "adaptive_auth_hours": 0, "admin_email": "homer.simpson@simpsons.com", "allow_factor_u2f": false, "device_certificate_policy": "no action", "allow_factor_phone": false, "local_trusted_sessions_display_val": 0, "allow_adaptive_auth": false, "local_trusted_sessions_display_unit": "days", "allow_factor_sms": false}',
                "isotimestamp": "2022-02-21 21:48:48",
                "object": "Global Policy",
                "timestamp": "2022-02-21 21:48:48",
                "username": "Homer Simpson",
            },
        ),
        RuleTest(
            name="Other event",
            expected_result=False,
            log={
                "action": "admin_login",
                "description": '{"ip_address": "1.2.3.4", "device": "123-456-123", "factor": "sms", "saml_idp": "OneLogin", "primary_auth_method": "Single Sign-On"}',
                "isotimestamp": "2021-07-02 18:31:25",
                "timestamp": "2021-07-02 18:31:25",
                "username": "Homer Simpson",
            },
        ),
    ]
