import json

from panther_detection_helpers.caching import add_to_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.auth0 import auth0_alert_context


@panther_managed
class Auth0SamePhoneMultipleUsersMFA(Rule):
    default_description = "Detecs when more than one user shares a phone number with another for MFA purposes. Attackers may register their phone number for multiple compromised accounts."
    display_name = "Auth0 Same Phone Number Shared Across Multiple Users as MFA"
    default_runbook = "Assess if this was done by the user for a valid business reason. Be vigilant to re-enable this setting as it's in the best security interest for your organization's security posture."
    default_reference = "https://github.com/auth0/auth0-customer-detections/tree/main/detections/multiple_phone_numbers_are_registered_as_mfa.yml"
    default_severity = Severity.HIGH
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    log_types = [LogType.AUTH0_EVENTS]
    id = "Auth0.SamePhone.MultipleUsers.MFA-prototype"
    RULE_ID = "Auth0.SamePhone.MultipleUsers.MFA"

    def rule(self, event):
        data_type = event.deep_get("data", "type", default="<NO_TYPE_FOUND>")
        data_description = event.deep_get("data", "description", default="<NO_DATA_DESCRIPTION_FOUND>")
        user_id = event.deep_get("data", "user_id", default="<NO_USER_ID_FOUND>")
        phone_number = str(
            event.deep_get("data", "details", "authenticator", "phone_number", default="<NO_PHONE_NUMBER_FOUND>"),
        )
        if (
            data_type != "gd_enrollment_complete"
            or data_description != "Guardian - Enrollment complete (sms)"
            or (not phone_number)
        ):
            return False
        key = phone_number + "-" + self.RULE_ID
        user_set = add_to_string_set(key, [user_id])
        if isinstance(user_set, str):
            # This is a unit test
            user_set = json.loads(user_set) if user_set else []
        return len(user_set) > 1

    def title(self, event):
        user_id = event.deep_get("data", "user_id", default="<NO_USER_ID_FOUND>")
        user = event.deep_get("data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>")
        phone_number = event.deep_get(
            "data",
            "details",
            "authenticator",
            "phone_number",
            default="<NO_PHONE_NUMBER_FOUND>",
        )
        p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL_FOUND>")
        return f"Auth0 User [{user}] having user_id [{user_id}] shares phone number [{phone_number}] as MFA in your organization's tenant [{p_source_label}]."

    def alert_context(self, event):
        return auth0_alert_context(event)

    tests = [
        RuleTest(
            name="Shared Phone Number as MFA",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="add_to_string_set",
                    return_value='["google-oauth2|999999999999999999999", "google-oauth2|105261262156475850461"]',
                ),
            ],
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-03 14:09:32.149000000",
                    "description": "Guardian - Enrollment complete (sms)",
                    "details": {
                        "authenticator": {"phone_number": 1234567891},
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000ecaf1bfbadb06900d22049"},
                                "strategy": "jwt",
                                "user": {"email": "eve@lexcorp.com", "name": "Homer Simpson"},
                            },
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {"body": [], "statusCode": 200},
                    },
                    "ip": "12.12.12.12",
                    "log_id": "90020230523204756343781000000000000001223372037583230452",
                    "type": "gd_enrollment_complete",
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
            name="First Time Phone Number Registration",
            expected_result=False,
            mocks=[RuleMock(object_name="add_to_string_set", return_value='["google-oauth2|105261262156475850461"]')],
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-03 14:09:32.149000000",
                    "description": "Guardian - Enrollment complete (sms)",
                    "details": {
                        "authenticator": {"phone_number": 1234567891},
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000ecaf1bfbadb06900d22049"},
                                "strategy": "jwt",
                                "user": {"email": "eve@lexcorp.com", "name": "Homer Simpson"},
                            },
                            "channel": "https://manage.auth0.com/",
                            "ip": "12.12.12.12",
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {"body": [], "statusCode": 200},
                    },
                    "ip": "12.12.12.12",
                    "log_id": "90020230523204756343781000000000000001223372037583230452",
                    "type": "gd_enrollment_complete",
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
            name="Same Phone Number for Same User",
            expected_result=False,
            mocks=[RuleMock(object_name="add_to_string_set", return_value='["google-oauth2|888888888888888888888"]')],
            log={
                "data": {
                    "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                    "client_name": "",
                    "date": "2025-10-03 14:09:32.149000000",
                    "description": "Guardian - Enrollment complete (sms)",
                    "details": {
                        "authenticator": {"phone_number": 5555555555},
                        "request": {
                            "auth": {
                                "credentials": {"jti": "0000000000ecaf1bfbadb06900d22049"},
                                "strategy": "jwt",
                                "user": {"email": "denethor@lotr.com", "name": "Different User"},
                            },
                            "channel": "https://manage.auth0.com/",
                            "ip": "10.10.10.10",
                            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                        },
                        "response": {"body": [], "statusCode": 200},
                    },
                    "ip": "10.10.10.10",
                    "log_id": "90020230523204756343781000000000000001223372037583230453",
                    "type": "gd_enrollment_complete",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Safari/537.36",
                    "user_id": "google-oauth2|888888888888888888888",
                },
                "log_id": "90020230523204756343781000000000000001223372037583230453",
                "p_any_ip_addresses": ["10.10.10.10"],
                "p_any_usernames": ["google-oauth2|888888888888888888888"],
                "p_event_time": "2023-05-23 20:47:51.149",
                "p_log_type": "Auth0.Events",
                "p_parse_time": "2023-05-23 20:49:28.671",
                "p_row_id": "00000000004a745ce33b57be383c543f",
                "p_schema_version": 0,
                "p_source_id": "b9031579-b2c5-45c2-b15c-632b995a4e36",
                "p_source_label": "Org Auth0 Tenant Label",
            },
        ),
    ]
