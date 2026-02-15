from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.auth0 import auth0_alert_context, is_auth0_config_event


@panther_managed
class Auth0RapidDynamicClientCreation(Rule):
    id = "Auth0.Rapid.DynamicClient.Creation-prototype"
    log_types = [LogType.AUTH0_EVENTS]
    display_name = "Auth0 Rapid Dynamic Client Creation"
    default_description = "Detects a spike in registered dynamic clients. This can indicate attempts to use such dynamic clients for malicious purposes."
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_reference = "https://github.com/auth0/auth0-customer-detections/blob/main/detections/rapid_creation_of_clients_with_dynamic_registration.yml"
    threshold = 15

    def rule(self, event):
        data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
        data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")
        return all(
            [is_auth0_config_event(event), data_type == "sapi", data_description == "Dynamic client registration"],
        )

    def title(self, event):
        client_id = event.deep_get("data", "details", "response", "body", "client_id", default="<NO_CLIENT_ID_FOUND")
        data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
        p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
        return f"Auth0 Significant number of Dynamic Client registration of [{data_description}] with client id [{client_id}] in your organization's tenant [{p_source_label}]."

    def alert_context(self, event):
        return auth0_alert_context(event)

    tests = [
        RuleTest(
            name="Auth0 Excessive Number of Dynamic Client Registered",
            expected_result=True,
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-10 10:27:51.149000000",
                    "description": "Dynamic client registration",
                    "details": {
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000311abf72f7a0ce7a303592"},
                                "strategy": "jwt",
                                "user": {
                                    "email": "denethor@lotr.com",
                                    "name": "Homer Simpson",
                                    "user_id": "google-oauth2|105261262156475850461",
                                },
                            },
                            "body": {"integration_id": "64bee519-818f-4473-ab08-7c380f28da77"},
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "method": "post",
                            "path": "/api/v2/integrations/installed",
                            "query": {},
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {
                            "body": {
                                "integration_id": "64bee519-818f-4473-ab08-7c380f28da77",
                                "client_id": "64bee519-818f-4473-ab08-7c380f28da77",
                            },
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
            },
        ),
        RuleTest(
            name="Other Event",
            expected_result=False,
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-10 10:27:51.149000000",
                    "description": "Guardian - Enrollment complete (sms)",
                    "details": {
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000311abf72f7a0ce7a303592"},
                                "strategy": "jwt",
                                "user": {
                                    "email": "denethor@lotr.com",
                                    "name": "Homer Simpson",
                                    "user_id": "google-oauth2|105261262156475850461",
                                },
                            },
                            "body": {"integration_id": "64bee519-818f-4473-ab08-7c380f28da77"},
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "method": "post",
                            "path": "/api/v2/integrations/installed",
                            "query": {},
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {
                            "body": {
                                "integration_id": "64bee519-818f-4473-ab08-7c380f28da77",
                                "client_id": "64bee519-818f-4473-ab08-7c380f28da77",
                            },
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
            },
        ),
    ]
