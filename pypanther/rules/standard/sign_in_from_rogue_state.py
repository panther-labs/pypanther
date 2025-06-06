import pycountry

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers import event_type


@panther_managed
class StandardSignInFromRogueState(Rule):
    id = "Standard.SignInFromRogueState-prototype"
    display_name = "Sign In from Rogue State"
    log_types = [
        LogType.ASANA_AUDIT,
        LogType.ATLASSIAN_AUDIT,
        LogType.AWS_CLOUDTRAIL,
        LogType.AZURE_AUDIT,
        LogType.BOX_EVENT,
        LogType.NOTION_AUDIT_LOGS,
        LogType.OKTA_SYSTEM_LOG,
        LogType.ONELOGIN_EVENTS,
        LogType.ONEPASSWORD_SIGN_IN_ATTEMPT,
        LogType.ZENDESK_AUDIT,
        LogType.ZOOM_ACTIVITY,
    ]
    default_severity = Severity.MEDIUM
    reports = {"MITRE ATT&CK": ["TA0001:T1078.004"]}
    default_description = "Detects when an entity signs in from a nation associated with cyber attacks"
    tags = ["DataModel", "Configuration Required"]
    # Configuration Required:
    #   Configure the below list of rogue states according to your needs/experience
    #   Refer to the link below to find the alpha-2 code corresponding to your country
    #   https://www.iban.com/country-codes
    ROGUE_STATES = {"CN", "IR", "RU"}

    def rule(self, event):
        # Only evaluate successful logins
        if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
            return False
        # Ignore events with no IP data
        if not event.udm("source_ip"):
            return False
        # Get contry of request origin and compare to identified rogue state list
        country = self.get_country(event)
        if country is None:
            # We weren't able to find a matching country, therefore we don't have enough information
            #   to alert on
            return False
        #   Wrapping in 'bool' so that we can use mocking for 'is_rogue_state'
        return bool(self.is_rogue_state(country.alpha_2))

    def title(self, event):
        log_type = event.get("p_log_type")
        country = self.get_country(event)
        account_name = self.get_account_name(event)
        return f"{log_type}: Sign-In for account {account_name} from Rogue State '{country.name}'"

    def alert_context(self, event):
        return {
            "source_ip": event.udm("source_ip"),
            "country": self.get_country(event).name,
            "account_name": self.get_account_name(event),
        }

    def get_country(self, event) -> str:
        """Returns the country code from an event's IPinfo data."""
        location_data = event.deep_get("p_enrichment", "ipinfo_location", event.udm_path("source_ip"))
        if not location_data:
            return None  # Ignore event if we have no enrichment to analyze
        return pycountry.countries.get(alpha_2=location_data.get("country").upper())

    def get_account_name(self, event) -> str:
        """Returns the account name."""
        if account_name := event.udm("actor_user"):
            return account_name
        return "UNKNWON ACCOUNT"

    def is_rogue_state(self, country_code: str) -> bool:
        """Returns whether the country code provided belongs to an identified rogue state."""
        # This function makes it easy for us to use unit test mocks to ensure altering the ROGUE_STATES
        #   dict doesn't break our test suite.
        return country_code in self.ROGUE_STATES

    tests = [
        RuleTest(
            name="Non-Sign-In Event",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "dude.lightbulb@example.co",
                    "displayName": "Dude Lightbulb",
                    "id": "EXAMPLE_ACTOR_ID",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "EXAMPLE_SESSION_ID"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Winnipeg",
                        "country": "Canada",
                        "geolocation": {"lat": 49.922, "lon": -96.965},
                        "postalCode": "R2C",
                        "state": "Manitoba",
                    },
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "displayMessage": "User single sign on to app",
                "eventType": "user.authentication.sso",
                "legacyEventType": "app.auth.sso",
                "outcome": {"result": "SUCCESS"},
                "p_any_ip_addresses": ["1.1.1.1"],
                "p_enrichment": {
                    "ipinfo_location": {
                        "client.ipAddress": {
                            "city": "Winnipeg",
                            "country": "CA",
                            "lat": "49.8844",
                            "lng": "-97.14704",
                            "p_match": "1.1.1.1",
                            "postal_code": "R3B",
                            "region": "Manitoba",
                            "region_code": "MB",
                            "timezone": "America/Winnipeg",
                        },
                    },
                },
                "p_log_type": "Okta.SystemLog",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Winnipeg",
                                "country": "Canada",
                                "geolocation": {"lat": 49.922, "lon": -96.965},
                                "postalCode": "R2C",
                                "state": "Manitoba",
                            },
                            "ip": "1.1.1.1",
                            "version": "V4",
                        },
                    ],
                },
                "severity": "INFO",
                "transaction": {"detail": {}, "id": "a33d5f8d1669b80efb7338791e222908", "type": "WEB"},
                "uuid": "6270d421-5be3-11ef-9376-abec352bd6d0",
                "version": "0",
            },
        ),
        RuleTest(
            name="Sign-In From Inconspicuous State",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "dude.lightbulb@example.co",
                    "displayName": "Dude Lightbulb",
                    "id": "EXAMPLE_USER_ID",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "EXAMPLE_SESSION_ID"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Winnipeg",
                        "country": "Canada",
                        "geolocation": {"lat": 49.922, "lon": -96.965},
                        "postalCode": "R2C",
                        "state": "Manitoba",
                    },
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "xxx",
                        "deviceFingerprint": "xxx",
                        "dtHash": "xxx",
                        "logOnlySecurityData": '{"risk":{"level":"LOW"},"behaviors":{"New Geo-Location":"NEGATIVE","New Device":"NEGATIVE","New IP":"NEGATIVE","New State":"NEGATIVE","New Country":"NEGATIVE","Velocity":"NEGATIVE","New City":"NEGATIVE"}}',
                        "oktaUserAgentExtended": "okta-auth-js/7.7.0 okta-signin-widget-7.21.0",
                        "origin": "https://example.okta.com",
                        "requestId": "xxx",
                        "requestUri": "/idp/idx/identify",
                        "threatSuspected": "false",
                        "url": "/idp/idx/identify?",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_success",
                "outcome": {"result": "SUCCESS"},
                "p_enrichment": {
                    "ipinfo_location": {
                        "client.ipAddress": {
                            "city": "Winnipeg",
                            "country": "CA",
                            "lat": "49.8844",
                            "lng": "-97.14704",
                            "p_match": "1.1.1.1",
                            "postal_code": "R3B",
                            "region": "Manitoba",
                            "region_code": "MB",
                            "timezone": "America/Winnipeg",
                        },
                    },
                },
                "p_event_time": "2024-08-15 15:05:09.154000000",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "2024-08-15 15:08:22.176160519",
                "p_row_id": "526383f6c367e7f3db88959621afee19",
                "p_source_id": "d0907120-58a3-4e40-acfa-e631693f9066",
                "p_source_label": "My Log Source",
                "published": "2024-08-15 15:05:09.154000000",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Winnipeg",
                                "country": "Canada",
                                "geolocation": {"lat": 49.922, "lon": -96.965},
                                "postalCode": "R2C",
                                "state": "Manitoba",
                            },
                            "ip": "1.1.1.1",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 7122,
                    "asOrg": "SAMPLE_ISP",
                    "domain": "isp.net",
                    "isProxy": False,
                    "isp": "SAMPLE_ISP",
                },
                "severity": "INFO",
                "target": [
                    {"alternateId": "My Okta App", "displayName": "My Okta App", "id": "xxx", "type": "AppInstance"},
                ],
                "transaction": {"detail": {}, "id": "32caf8cb5819a0928702b4b835e163a0", "type": "WEB"},
                "uuid": "c35900e7-5b17-11ef-ad6d-cf78a9534d8d",
                "version": "0",
            },
        ),
        RuleTest(
            name="Sign-In with no Enrichment Data",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "dude.lightbulb@example.co",
                    "displayName": "Dude Lightbulb",
                    "id": "EXAMPLE_USER_ID",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "EXAMPLE_SESSION_ID"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Winnipeg",
                        "country": "Canada",
                        "geolocation": {"lat": 49.922, "lon": -96.965},
                        "postalCode": "R2C",
                        "state": "Manitoba",
                    },
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "xxx",
                        "deviceFingerprint": "xxx",
                        "dtHash": "xxx",
                        "logOnlySecurityData": '{"risk":{"level":"LOW"},"behaviors":{"New Geo-Location":"NEGATIVE","New Device":"NEGATIVE","New IP":"NEGATIVE","New State":"NEGATIVE","New Country":"NEGATIVE","Velocity":"NEGATIVE","New City":"NEGATIVE"}}',
                        "oktaUserAgentExtended": "okta-auth-js/7.7.0 okta-signin-widget-7.21.0",
                        "origin": "https://example.okta.com",
                        "requestId": "xxx",
                        "requestUri": "/idp/idx/identify",
                        "threatSuspected": "false",
                        "url": "/idp/idx/identify?",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_success",
                "outcome": {"result": "SUCCESS"},
                "p_event_time": "2024-08-15 15:05:09.154000000",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "2024-08-15 15:08:22.176160519",
                "p_row_id": "526383f6c367e7f3db88959621afee19",
                "p_source_id": "d0907120-58a3-4e40-acfa-e631693f9066",
                "p_source_label": "My Log Source",
                "published": "2024-08-15 15:05:09.154000000",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Winnipeg",
                                "country": "Canada",
                                "geolocation": {"lat": 49.922, "lon": -96.965},
                                "postalCode": "R2C",
                                "state": "Manitoba",
                            },
                            "ip": "1.1.1.1",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 7122,
                    "asOrg": "SAMPLE_ISP",
                    "domain": "isp.net",
                    "isProxy": False,
                    "isp": "SAMPLE_ISP",
                },
                "severity": "INFO",
                "target": [
                    {"alternateId": "My Okta App", "displayName": "My Okta App", "id": "xxx", "type": "AppInstance"},
                ],
                "transaction": {"detail": {}, "id": "32caf8cb5819a0928702b4b835e163a0", "type": "WEB"},
                "uuid": "c35900e7-5b17-11ef-ad6d-cf78a9534d8d",
                "version": "0",
            },
        ),
        RuleTest(
            name="Sign-In From Country That Doesn't Exist",
            expected_result=False,
            log={
                "actor": {
                    "alternateId": "dude.lightbulb@example.co",
                    "displayName": "Dude Lightbulb",
                    "id": "EXAMPLE_USER_ID",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "EXAMPLE_SESSION_ID"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Winnipeg",
                        "country": "Canada",
                        "geolocation": {"lat": 49.922, "lon": -96.965},
                        "postalCode": "R2C",
                        "state": "Manitoba",
                    },
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "xxx",
                        "deviceFingerprint": "xxx",
                        "dtHash": "xxx",
                        "logOnlySecurityData": '{"risk":{"level":"LOW"},"behaviors":{"New Geo-Location":"NEGATIVE","New Device":"NEGATIVE","New IP":"NEGATIVE","New State":"NEGATIVE","New Country":"NEGATIVE","Velocity":"NEGATIVE","New City":"NEGATIVE"}}',
                        "oktaUserAgentExtended": "okta-auth-js/7.7.0 okta-signin-widget-7.21.0",
                        "origin": "https://example.okta.com",
                        "requestId": "xxx",
                        "requestUri": "/idp/idx/identify",
                        "threatSuspected": "false",
                        "url": "/idp/idx/identify?",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_success",
                "outcome": {"result": "SUCCESS"},
                "p_enrichment": {
                    "ipinfo_location": {
                        "client.ipAddress": {
                            "city": "Winnipeg",
                            "country": "FAKE_COUNTRY",
                            "lat": "49.8844",
                            "lng": "-97.14704",
                            "p_match": "1.1.1.1",
                            "postal_code": "R3B",
                            "region": "Manitoba",
                            "region_code": "MB",
                            "timezone": "America/Winnipeg",
                        },
                    },
                },
                "p_event_time": "2024-08-15 15:05:09.154000000",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "2024-08-15 15:08:22.176160519",
                "p_row_id": "526383f6c367e7f3db88959621afee19",
                "p_source_id": "d0907120-58a3-4e40-acfa-e631693f9066",
                "p_source_label": "My Log Source",
                "published": "2024-08-15 15:05:09.154000000",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Winnipeg",
                                "country": "Canada",
                                "geolocation": {"lat": 49.922, "lon": -96.965},
                                "postalCode": "R2C",
                                "state": "Manitoba",
                            },
                            "ip": "1.1.1.1",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 7122,
                    "asOrg": "SAMPLE_ISP",
                    "domain": "isp.net",
                    "isProxy": False,
                    "isp": "SAMPLE_ISP",
                },
                "severity": "INFO",
                "target": [
                    {"alternateId": "My Okta App", "displayName": "My Okta App", "id": "xxx", "type": "AppInstance"},
                ],
                "transaction": {"detail": {}, "id": "32caf8cb5819a0928702b4b835e163a0", "type": "WEB"},
                "uuid": "c35900e7-5b17-11ef-ad6d-cf78a9534d8d",
                "version": "0",
            },
        ),
        RuleTest(
            name="Asana - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "actor": {
                    "actor_type": "user",
                    "email": "dude.lightbulb@example.co",
                    "gid": "xxx",
                    "name": "Dude Lightbulb",
                },
                "context": {
                    "client_ip_address": "1.1.1.1",
                    "context_type": "web",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
                },
                "created_at": "2023-02-16 06:47:34.903",
                "details": {"method": ["SAML"]},
                "event_category": "logins",
                "event_type": "user_login_succeeded",
                "gid": "xxx",
                "p_enrichment": {
                    "ipinfo_location": {
                        "context.client_ip_address": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_event_time": "2023-02-16 06:47:34.903",
                "p_log_type": "Asana.Audit",
                "p_parse_time": "2023-02-16 06:53:22.561",
                "p_row_id": "22bc6744332dc49e86f4a9b816f18a0f",
                "p_schema_version": 0,
                "p_source_id": "46bc875b-172f-4e9b-b475-6efac507c9a2",
                "p_source_label": "Asana",
                "resource": {
                    "email": "dude.lightbulb@example.co",
                    "gid": "xxx",
                    "name": "Dude Lightbulb",
                    "resource_type": "user",
                },
            },
        ),
        RuleTest(
            name="Azure - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "calleripaddress": "12.12.12.12",
                "category": "ServicePrincipalSignInLogs",
                "correlationid": "bf12205b-eea0-43dd-ad6d-b9030dc62a7a",
                "durationms": 0,
                "level": 4,
                "location": "US",
                "operationname": "Sign-in activity",
                "operationversion": 1,
                "p_enrichment": {
                    "ipinfo_location": {
                        "properties.ipAddress": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_log_type": "Azure.Audit",
                "properties": {
                    "appId": "3b245ca3-dcce-4a54-a070-49ad8de02963",
                    "authenticationProcessingDetails": [
                        {
                            "key": "Azure AD App Authentication Library",
                            "value": "Family: Unknown Library: Unknown 1.0.0 Platform: Unknown",
                        },
                    ],
                    "authenticationProtocol": "none",
                    "clientCredentialType": "none",
                    "conditionalAccessStatus": "notApplied",
                    "correlationId": "52d1e530-786c-443c-8dc8-aa7b1317608e",
                    "createdDateTime": "2023-07-27 13:59:53.691680300",
                    "crossTenantAccessType": "none",
                    "flaggedForReview": False,
                    "id": "55270060-d8fe-435e-9bf2-219a1d456b60",
                    "incomingTokenType": "none",
                    "ipAddress": "12.12.12.12",
                    "isInteractive": False,
                    "isTenantRestricted": False,
                    "location": {
                        "city": "Springfield",
                        "countryOrRegion": "US",
                        "geoCoordinates": {"latitude": 42.73333333333333, "longitude": -110.88888888888889},
                        "state": "Oregon",
                    },
                    "managedIdentityType": "none",
                    "processingTimeInMilliseconds": 0,
                    "resourceDisplayName": "Office 365 Management APIs",
                    "resourceId": "9cc31481-8822-49ff-b638-552ecc26c777",
                    "resourceServicePrincipalId": "2acf8174-5e07-4ec4-9de8-08d880129ba5",
                    "riskDetail": "none",
                    "riskLevelAggregated": "low",
                    "riskLevelDuringSignIn": "low",
                    "riskState": "none",
                    "servicePrincipalCredentialKeyId": "2afc776a-4e79-4588-b2ad-f62c94d6bea8",
                    "servicePrincipalId": "4b6986ec-c49c-40c0-89ce-b2ac51213e39",
                    "servicePrincipalName": "very-normal-service-principal",
                    "status": {"errorCode": 0},
                    "tokenIssuerType": "AzureAD",
                    "uniqueTokenIdentifier": "CXXXXXXXXXXXXXXXXXXXXX",
                },
                "resourceid": "/tenants/60641ed1-32f7-4a2e-a912-d724c497e1e9/providers/Microsoft.aadiam",
                "resultsignature": "None",
                "resulttype": 0,
                "tenantid": "85e54ec3-85ee-4b03-9e3b-863075eb9b62",
                "time": "2023-07-27 14:00:41.848",
            },
        ),
        RuleTest(
            name="Box - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "type": "event",
                "additional_details": '{"key": "value"}',
                "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"},
                "event_type": "LOGIN",
                "ip_address": "1.1.1.1",
                "p_enrichment": {
                    "ipinfo_location": {
                        "ip_address": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_log_type": "Box.Event",
                "source": {"id": "12345678", "type": "user", "login": "user@example"},
            },
        ),
        RuleTest(
            name="Cloudtrail - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "additionalEventData": {"MFAUsed": "No", "MobileVersion": "No"},
                "awsRegion": "us-east-1",
                "eventCategory": "Management",
                "eventName": "ConsoleLogin",
                "eventSource": "signin.amazonaws.com",
                "eventTime": "2023-05-26 20:14:51",
                "eventType": "AwsConsoleSignIn",
                "eventVersion": "1.08",
                "managementEvent": True,
                "p_event_time": "2023-05-26 20:14:51",
                "p_enrichment": {
                    "ipinfo_location": {
                        "load_ip_address": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_log_type": "AWS.CloudTrail",
                "p_parse_time": "2023-05-26 20:19:14.002",
                "p_source_label": "LogSource Name",
                "readOnly": False,
                "recipientAccountId": "123456789012",
                "responseElements": {"ConsoleLogin": "Success"},
                "sourceIPAddress": "12.12.12.12",
                "tlsDetails": {
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "signin.aws.amazon.com",
                    "tlsVersion": "TLSv1.3",
                },
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::123456789012:user/tester",
                    "accountId": "123456789012",
                    "userName": "tester",
                },
            },
        ),
        RuleTest(
            name="Notion - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "event": {
                    "actor": {
                        "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "object": "user",
                        "person": {"email": "aragorn.elessar@lotr.com"},
                        "type": "person",
                    },
                    "details": {"authType": "saml"},
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "ip_address": "192.168.100.100",
                    "timestamp": "2023-10-03T19:02:28.044000Z",
                    "type": "user.login",
                    "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                },
                "p_enrichment": {
                    "ipinfo_location": {
                        "event.ip_address": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_event_time": "2023-10-03T19:02:28.044000Z",
                "p_log_type": "Notion.AuditLogs",
                "p_source_label": "Notion-Panther-Labs",
            },
        ),
        RuleTest(
            name="Okta - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "actor": {
                    "alternateId": "dude.lightbulb@example.co",
                    "displayName": "Dude Lightbulb",
                    "id": "EXAMPLE_USER_ID",
                    "type": "User",
                },
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "EXAMPLE_SESSION_ID"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Moscow",
                        "country": "Russia",
                        "geolocation": {"lat": 55.752, "lon": 37.615},
                        "postalCode": "119021",
                        "state": "Moscow",
                    },
                    "ipAddress": "1.1.1.1",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Mac OS X",
                        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "authnRequestId": "xxx",
                        "deviceFingerprint": "xxx",
                        "dtHash": "xxx",
                        "logOnlySecurityData": '{"risk":{"level":"LOW"},"behaviors":{"New Geo-Location":"NEGATIVE","New Device":"NEGATIVE","New IP":"NEGATIVE","New State":"NEGATIVE","New Country":"NEGATIVE","Velocity":"NEGATIVE","New City":"NEGATIVE"}}',
                        "oktaUserAgentExtended": "okta-auth-js/7.7.0 okta-signin-widget-7.21.0",
                        "origin": "https://example.okta.com",
                        "requestId": "xxx",
                        "requestUri": "/idp/idx/identify",
                        "threatSuspected": "false",
                        "url": "/idp/idx/identify?",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_success",
                "outcome": {"result": "SUCCESS"},
                "p_enrichment": {
                    "ipinfo_location": {
                        "client.ipAddress": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_event_time": "2024-08-15 15:05:09.154000000",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "2024-08-15 15:08:22.176160519",
                "p_row_id": "526383f6c367e7f3db88959621afee19",
                "p_source_id": "d0907120-58a3-4e40-acfa-e631693f9066",
                "p_source_label": "My Log Source",
                "published": "2024-08-15 15:05:09.154000000",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Moscow",
                                "country": "Russia",
                                "geolocation": {"lat": 55.752, "lon": 37.615},
                                "postalCode": "119021",
                                "state": "Moscow",
                            },
                            "ip": "1.1.1.1",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 7122,
                    "asOrg": "SAMPLE_ISP",
                    "domain": "isp.net",
                    "isProxy": False,
                    "isp": "SAMPLE_ISP",
                },
                "severity": "INFO",
                "target": [
                    {"alternateId": "My Okta App", "displayName": "My Okta App", "id": "xxx", "type": "AppInstance"},
                ],
                "transaction": {"detail": {}, "id": "32caf8cb5819a0928702b4b835e163a0", "type": "WEB"},
                "uuid": "c35900e7-5b17-11ef-ad6d-cf78a9534d8d",
                "version": "0",
            },
        ),
        RuleTest(
            name="OneLogin - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "event_type_id": "5",
                "actor_user_id": 123456,
                "actor_user_name": "Bob Cat",
                "ipaddr": "1.1.1.1",
                "p_enrichment": {
                    "ipinfo_location": {
                        "ipaddr": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_log_type": "OneLogin.Events",
                "user_id": 123456,
                "user_name": "Bob Cat",
            },
        ),
        RuleTest(
            name="OnePassword - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "category": "success",
                "client": {
                    "app_name": "1Password Browser Extension",
                    "app_version": "22600103",
                    "ip_address": "1.1.1.1",
                    "os_name": "MacOSX",
                    "os_version": "10.15",
                    "platform_name": "Firefox extension",
                    "platform_version": "128.0",
                },
                "country": "RU",
                "location": {
                    "city": "Moscow",
                    "country": "RU",
                    "latitude": 55.752,
                    "longitude": 37.615,
                    "region": "Moscow",
                },
                "p_enrichment": {
                    "ipinfo_location": {
                        "client.ip_address": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_event_time": "2024-08-16 19:18:43.784550714",
                "p_log_type": "OnePassword.SignInAttempt",
                "p_parse_time": "2024-08-16 19:28:04.114167542",
                "p_row_id": "ded6c31fcf859c8fd1f7fc9821e3b703",
                "p_schema_version": 0,
                "p_source_id": "9f722ac4-3715-4db8-a0b4-a62f34599f90",
                "p_source_label": "1Password",
                "session_uuid": "EXAMPLE_SESSION_ID",
                "target_user": {
                    "email": "dude.lightbulb@example.co",
                    "name": "Dude Lightbulb",
                    "uuid": "EXAMPLE_PROVIDER_ID",
                },
                "timestamp": "2024-08-16 19:18:43.784550714",
                "type": "credentials_ok",
                "uuid": "EXAMPLE_UUID",
            },
        ),
        RuleTest(
            name="Zoom - Rogue State Sign-In",
            expected_result=True,
            mocks=[RuleMock(object_name="is_rogue_state", return_value=True)],
            log={
                "client_type": "mac",
                "email": "dude.lightbulb@example.co",
                "ip_address": "1.1.1.1",
                "p_enrichment": {
                    "ipinfo_location": {
                        "ip_address": {
                            "city": "Moscow",
                            "country": "RU",
                            "lat": "55.7520",
                            "lng": "37.6150",
                            "p_match": "1.1.1.1",
                            "postal_code": "119021",
                            "region": "Moscow",
                            "region_code": "RU",
                            "timezone": "Europe/Moscow",
                        },
                    },
                },
                "p_event_time": "2023-08-14 16:17:05",
                "p_log_type": "Zoom.Activity",
                "p_parse_time": "2023-08-14 16:22:14.232",
                "p_row_id": "d2cc7476479cc4b1e3a0bbfb1901",
                "p_schema_version": 0,
                "p_source_id": "afedae15-43e8-45d1-85e6-8f525e176d3e",
                "p_source_label": "Zoom",
                "time": "2023-08-14 16:17:05",
                "type": "Sign in",
                "version": "5.15.7.21404",
            },
        ),
    ]
