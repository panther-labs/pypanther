from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.auth0 import auth0_alert_context, is_auth0_config_event


@panther_managed
class Auth0BotDetectionDisabled(Rule):
    default_description = "A bot detection policy was disabled."
    display_name = "Auth0 Bot Detection Policy Disabled"
    default_runbook = "Assess if this was done by the user for a valid business reason. Be vigilant to re-enable this setting as it's in the best security interest for your organization's security posture."
    default_reference = "https://github.com/auth0/auth0-customer-detections/tree/main/detections"
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0005:T1562"]}
    log_types = [LogType.AUTH0_EVENTS]
    id = "Auth0.BotDetection.Disabled-prototype"

    def rule(self, event):
        data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")
        data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
        bot_p_policy = event.deep_get(
            "data",
            "details",
            "response",
            "body",
            "passwordless_policy",
            default="<NO_PASSWORDLESS_POLICY_FOUND>",
        )
        bot_reset_policy = event.deep_get(
            "data",
            "details",
            "response",
            "body",
            "password_reset_policy",
            default="<NO_PASSWORD_RESET_POLICY_FOUND>",
        )
        bot_policy = event.deep_get("data", "details", "response", "body", "policy", default="<NO_BOT_POLICY_FOUND>")
        response_status_code = event.deep_get(
            "data",
            "details",
            "response",
            "statusCode",
            default="<NO_RESPONSE_CODE_FOUND>",
        )
        return all(
            [
                data_type == "sapi",
                data_description == "Create or update the anomaly detection captcha"
                and (bot_p_policy == "off" or bot_reset_policy == "off" or bot_policy == "off"),
                response_status_code == 200,
                is_auth0_config_event(event),
            ],
        )

    def title(self, event):
        user = event.deep_get("data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>")
        p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
        return f"Auth0 User [{user}] disabled bot detection in your organization's tenant [{p_source_label}]."

    def alert_context(self, event):
        return auth0_alert_context(event)

    tests = [
        RuleTest(
            name="Auth0 Bot Detection Policy Disabled",
            expected_result=True,
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-03 14:09:32.149000000",
                    "description": "Create or update the anomaly detection captcha",
                    "details": {
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000ecaf1bfbadb06900d22049"},
                                "strategy": "jwt",
                                "user": {
                                    "email": "denethor@lotr.com",
                                    "name": "Homer Simpson",
                                    "user_id": "google-oauth2|105261262156475850461",
                                },
                            },
                            "body": {"enabled": True},
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "method": "post",
                            "path": "/v2/attack-protection/bot-detection",
                            "query": {},
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {
                            "body": {"policy": "off", "password_reset_policy": "off", "passwordless_policy": "off"},
                            "statusCode": 200,
                        },
                    },
                    "ip": "12.12.12.12",
                    "log_id": "90020230523204756343781000000000000001223372037583230452",
                    "type": "sapi",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                    "user_id": "google-oauth2|105261262156475850461",
                },
                "log_id": "90020230523204756343781000000000000001223372037583230452",
                "p_any_ip_addresses": ["12.12.12.12"],
                "p_any_usernames": ["google-oauth2|105261262156475850461"],
                "p_event_time": "2023-05-23 20:47:51.149",
                "p_log_type": "Auth0.Events",
                "p_parse_time": "2023-05-23 20:49:28.671",
                "p_row_id": "00000000004a745ce33b57be383c543e",
                "p_schema_version": 0,
                "p_source_id": "b9031579-b2c5-45c2-b15c-632b995a4e36",
                "p_source_label": "Org Auth0 Tenant Label",
            },
        ),
        RuleTest(
            name="Enable Bot Detection Feature",
            expected_result=False,
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-03 14:09:32.149000000",
                    "description": "Create or update the anomaly detection captcha",
                    "details": {
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000ecaf1bfbadb06900d22049"},
                                "strategy": "jwt",
                                "user": {
                                    "email": "denethor@lotr.com",
                                    "name": "Homer Simpson",
                                    "user_id": "google-oauth2|105261262156475850461",
                                },
                            },
                            "body": {"enabled": True},
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "method": "post",
                            "path": "/v2/attack-protection/bot-detection",
                            "query": {},
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {"body": {"policy": "on"}, "statusCode": 200},
                    },
                    "ip": "12.12.12.12",
                    "log_id": "90020230523204756343781000000000000001223372037583230452",
                    "type": "sapi",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                    "user_id": "google-oauth2|105261262156475850461",
                },
                "log_id": "90020230523204756343781000000000000001223372037583230452",
                "p_any_ip_addresses": ["12.12.12.12"],
                "p_any_usernames": ["google-oauth2|105261262156475850461"],
                "p_event_time": "2023-05-23 20:47:51.149",
                "p_log_type": "Auth0.Events",
                "p_parse_time": "2023-05-23 20:49:28.671",
                "p_row_id": "00000000004a745ce33b57be383c543e",
                "p_schema_version": 0,
                "p_source_id": "b9031579-b2c5-45c2-b15c-632b995a4e36",
                "p_source_label": "Org Auth0 Tenant Label",
            },
        ),
    ]
