from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.auth0 import auth0_alert_context, is_auth0_config_event


@panther_managed
class Auth0NewAdminInvitation(Rule):
    id = "Auth0.NewAdmin.Invitation-prototype"
    display_name = "Auth0 New Admin Invited"
    log_types = [LogType.AUTH0_EVENTS]
    default_severity = Severity.INFO
    create_alert = False
    reports = {"MITRE ATT&CK": ["TA0003:T1136"]}
    default_description = "A new admin invitation was issued."
    default_reference = (
        "https://github.com/auth0/auth0-customer-detections/blob/main/detections/risk_of_tenant_takeover.yml"
    )

    def rule(self, event):
        data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
        roles = event.deep_get("data", "details", "request", "body", "roles", default="<NO_ROLE_FOUND>")
        return all(
            [
                is_auth0_config_event(event),
                data_description == "Create tenant invitations for a given client",
                "owner" in roles,
            ],
        )

    def alert_context(self, event):
        return auth0_alert_context(event)

    tests = [
        RuleTest(
            name="Successful Admin Invitation Issued",
            expected_result=True,
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-10 10:27:51.149000000",
                    "description": "Create tenant invitations for a given client",
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
                            "body": {
                                "integration_id": "64bee519-818f-4473-ab08-7c380f28da77",
                                "roles": ["owner", "user"],
                            },
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "method": "post",
                            "path": "/api/v2/integrations/installed",
                            "query": {},
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {
                            "body": {"integration_id": "64bee519-818f-4473-ab08-7c380f28da77"},
                            "statusCode": 200,
                        },
                    },
                    "ip": "12.12.12.12",
                    "log_id": "90020230523204756343781000000000000001223372037583230452",
                    "type": "signup_pwd_leak",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                    "user_id": "google-oauth2|105261262156475850461",
                },
                "log_id": "90020230523204756343781000000000000001223372037583230452",
            },
        ),
        RuleTest(
            name="Successful User Invitation Issued",
            expected_result=False,
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-10 10:27:51.149000000",
                    "description": "Create tenant invitations for a given client",
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
                            "body": {
                                "integration_id": "64bee519-818f-4473-ab08-7c380f28da77",
                                "roles": ["user", "user"],
                            },
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "method": "post",
                            "path": "/api/v2/integrations/installed",
                            "query": {},
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {
                            "body": {"integration_id": "64bee519-818f-4473-ab08-7c380f28da77"},
                            "statusCode": 200,
                        },
                    },
                    "ip": "12.12.12.12",
                    "log_id": "90020230523204756343781000000000000001223372037583230452",
                    "type": "signup_pwd_leak",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                    "user_id": "google-oauth2|105261262156475850461",
                },
                "log_id": "90020230523204756343781000000000000001223372037583230452",
            },
        ),
    ]
