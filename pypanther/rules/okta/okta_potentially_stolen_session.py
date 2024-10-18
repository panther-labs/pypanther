import json
from datetime import timedelta
from difflib import SequenceMatcher

from panther_detection_helpers.caching import get_string_set, put_string_set

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.okta import okta_alert_context


@panther_managed
class OktaPotentiallyStolenSession(Rule):
    id = "Okta.PotentiallyStolenSession-prototype"
    display_name = "Okta Potentially Stolen Session"
    log_types = [LogType.OKTA_SYSTEM_LOG]
    tags = ["Identity & Access Management", "Okta"]
    reports = {"MITRE ATT&CK": ["TA0006:T1539"]}
    default_severity = Severity.HIGH
    default_description = (
        "This rule looks for the same session being used from two devices, indicating a compromised session token."
    )
    default_runbook = "Confirm the session is used on two devices, one of which is unknown. Lock the users Okta account and clear the users sessions in down stream apps."
    default_reference = "https://sec.okta.com/sessioncookietheft"
    summary_attributes = ["eventType", "severity", "p_any_ip_addresses", "p_any_domain_names"]
    FUZZ_RATIO_MIN = 0.95
    PREVIOUS_SESSION = {}
    # the number of days an Okta session is valid for (configured in Okta)
    SESSION_TIMEOUT = timedelta(days=1).total_seconds()
    EVENT_TYPES = ("user.authentication.sso", "user.session.start")

    def rule(self, event):
        # ensure previous session info is avaialable in the alert_context for investigation
        session_id = event.deep_get("authenticationContext", "externalSessionId", default="unknown")
        dt_hash = event.deep_get("debugContext", "debugData", "dtHash", default="unknown")
        # Some events by Okta admins may appear to have changed IPs
        # and user agents due to internal Okta behavior:
        # https://support.okta.com/help/s/article/okta-integrations-showing-as-rawuseragent-with-okta-ips
        # As such, we ignore certain client ids known to originate from Okta:
        # https://developer.okta.com/docs/api/openapi/okta-myaccount/myaccount/tag/OktaApplications/
        if event.deep_get("client", "id") in ["okta.b58d5b75-07d4-5f25-bf59-368a1261a405"]:  # Admin Console
            return False
        # Filter only on app access and session start events
        if event.get("eventType") not in self.EVENT_TYPES or (session_id == "unknown" or dt_hash == "unknown"):
            return False
        key = session_id + "-" + dt_hash
        # lookup if we've previously stored the session cookie
        self.PREVIOUS_SESSION = get_string_set(key)
        # For unit test mocks we need to eval the string to a set
        if isinstance(self.PREVIOUS_SESSION, str):
            self.PREVIOUS_SESSION = set(json.loads(self.PREVIOUS_SESSION))
        # If the sessionID has not been seen before, store information about it
        if not self.PREVIOUS_SESSION:
            # clearly label the user agent string so we can find it during the comparison
            put_string_set(
                key,
                [
                    str(event.deep_get("securityContext", "asNumber")),
                    event.deep_get("client", "ipAddress"),
                    "user_agent:" + event.deep_get("client", "userAgent", "rawUserAgent"),
                    event.deep_get("client", "userAgent", "browser"),
                    event.deep_get("client", "userAgent", "os"),
                    event.get("p_event_time"),
                    "sign_on_mode:" + event.deep_get("debugContext", "debugData", "signOnMode", default="unknown"),
                    "threat_suspected:"
                    + event.deep_get("debugContext", "debugData", "threat_suspected", default="unknown"),
                ],
                epoch_seconds=event.event_time_epoch() + self.SESSION_TIMEOUT,
            )
        else:
            # if the session cookie was seen before
            # we use a fuzz match to compare the current and prev user agent.
            # We cannot do a direct match since Okta can occasionally maintain
            # a session across browser upgrades.
            # the user-agent was tagged during storage so we can find it, remove that tag
            [prev_ua] = [x for x in self.PREVIOUS_SESSION if "user_agent:" in x] or ["prev_ua_not_found"]
            prev_ua = prev_ua.split("_agent:")[1]
            diff_ratio = SequenceMatcher(
                None,
                event.deep_get("client", "userAgent", "rawUserAgent", default="ua_not_found"),
                prev_ua,
            ).ratio()
            # is this session being used from a new IP and a different browser
            if (
                str(event.deep_get("client", "ipAddress", default="ip_not_found")) not in self.PREVIOUS_SESSION
                and diff_ratio < self.FUZZ_RATIO_MIN
            ):
                # make the fuzz ratio available in the alert context
                self.PREVIOUS_SESSION.add("Fuzz Ratio: " + str(diff_ratio))
                return True
        return False

    def title(self, event):
        return f"Potentially Stolen Okta Session - {event.deep_get('actor', 'displayName', default='Unknown_user')}"

    def alert_context(self, event):
        context = okta_alert_context(event)
        context["previous_session"] = str(self.PREVIOUS_SESSION)
        return context

    tests = [
        RuleTest(
            name="Same device and OS",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="get_string_set",
                    return_value='[\n    "263297",\n    "1.2.3.4",\n    "user_agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36",\n    "CHROME",\n    "Linux"\n]\n',
                ),
            ],
            log={
                "actor": {"alternateId": "admin", "displayName": "unknown", "id": "unknown", "type": "User"},
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "123456789"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Dois Irmaos",
                        "country": "Brazil",
                        "geolocation": {"lat": -29.6116, "lon": -51.0933},
                        "postalCode": "93950",
                        "state": "Rio Grande do Sul",
                    },
                    "ipAddress": "1.2.3.4",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Linux",
                        "rawUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "loginResult": "VERIFICATION_ERROR",
                        "requestId": "redacted",
                        "requestUri": "redacted",
                        "threatSuspected": "false",
                        "url": "redacted",
                        "dtHash": "kzpx58a99d2oam082rlu588wgy1mb0zfi1e1l63f9cjx4uxc455k4t6xdiwbxian",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_failed",
                "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"},
                "p_any_domain_names": ["rnvtelecom.com.br"],
                "p_any_ip_addresses": ["redacted"],
                "p_event_time": "redacted",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "redacted",
                "p_row_id": "redacted",
                "p_source_id": "redacted",
                "p_source_label": "Okta",
                "published": "redacted",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Dois Irmaos",
                                "country": "Brazil",
                                "geolocation": {"lat": -29.6116, "lon": -51.0933},
                                "postalCode": "93950",
                                "state": "Rio Grande do Sul",
                            },
                            "ip": "redacted",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 263297,
                    "asOrg": "renovare telecom",
                    "domain": "rnvtelecom.com.br",
                    "isProxy": False,
                    "isp": "renovare telecom",
                },
                "severity": "INFO",
                "transaction": {"detail": {}, "id": "redacted", "type": "WEB"},
                "uuid": "redacted",
                "version": "0",
            },
        ),
        RuleTest(
            name="Different device & ASN",
            expected_result=True,
            mocks=[
                RuleMock(
                    object_name="get_string_set",
                    return_value='[\n    "123456",\n    "4.3.2.1",\n    "user_agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",\n    "CHROME",\n    "MacOS"\n]\n',
                ),
            ],
            log={
                "actor": {"alternateId": "admin", "displayName": "Bobert", "id": "unknown", "type": "User"},
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "123456789"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Dois Irmaos",
                        "country": "Brazil",
                        "geolocation": {"lat": -29.6116, "lon": -51.0933},
                        "postalCode": "93950",
                        "state": "Rio Grande do Sul",
                    },
                    "ipAddress": "1.2.3.4",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Linux",
                        "rawUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "dtHash": "kzpx58a99d2oam082rlu588wgy1mb0zfi1e1l63f9cjx4uxc455k4t6xdiwbxian",
                        "loginResult": "VERIFICATION_ERROR",
                        "requestId": "redacted",
                        "requestUri": "redacted",
                        "threatSuspected": "false",
                        "url": "redacted",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_failed",
                "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"},
                "p_any_domain_names": ["rnvtelecom.com.br"],
                "p_any_ip_addresses": ["redacted"],
                "p_event_time": "redacted",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "redacted",
                "p_row_id": "redacted",
                "p_source_id": "redacted",
                "p_source_label": "Okta",
                "published": "redacted",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Dois Irmaos",
                                "country": "Brazil",
                                "geolocation": {"lat": -29.6116, "lon": -51.0933},
                                "postalCode": "93950",
                                "state": "Rio Grande do Sul",
                            },
                            "ip": "redacted",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 263297,
                    "asOrg": "renovare telecom",
                    "domain": "rnvtelecom.com.br",
                    "isProxy": False,
                    "isp": "renovare telecom",
                },
                "severity": "INFO",
                "transaction": {"detail": {}, "id": "redacted", "type": "WEB"},
                "uuid": "redacted",
                "version": "0",
            },
        ),
        RuleTest(
            name="Different ASN & same device",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="get_string_set",
                    return_value='[\n    "654321",\n    "1.2.3.4",\n    "user_agent:Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36",\n    "CHROME",\n    "Linux"\n]\n',
                ),
            ],
            log={
                "actor": {"alternateId": "admin", "displayName": "Bobert", "id": "unknown", "type": "User"},
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "123456789"},
                "client": {
                    "device": "Computer",
                    "geographicalContext": {
                        "city": "Dois Irmaos",
                        "country": "Brazil",
                        "geolocation": {"lat": -29.6116, "lon": -51.0933},
                        "postalCode": "93950",
                        "state": "Rio Grande do Sul",
                    },
                    "ipAddress": "1.2.3.4",
                    "userAgent": {
                        "browser": "CHROME",
                        "os": "Linux",
                        "rawUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36",
                    },
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "loginResult": "VERIFICATION_ERROR",
                        "requestId": "redacted",
                        "requestUri": "redacted",
                        "threatSuspected": "false",
                        "url": "redacted",
                        "dtHash": "kzpx58a99d2oam082rlu588wgy1mb0zfi1e1l63f9cjx4uxc455k4t6xdiwbxian",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_failed",
                "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"},
                "p_any_domain_names": ["rnvtelecom.com.br"],
                "p_any_ip_addresses": ["redacted"],
                "p_event_time": "redacted",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "redacted",
                "p_row_id": "redacted",
                "p_source_id": "redacted",
                "p_source_label": "Okta",
                "published": "redacted",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Dois Irmaos",
                                "country": "Brazil",
                                "geolocation": {"lat": -29.6116, "lon": -51.0933},
                                "postalCode": "93950",
                                "state": "Rio Grande do Sul",
                            },
                            "ip": "redacted",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {
                    "asNumber": 263297,
                    "asOrg": "renovare telecom",
                    "domain": "rnvtelecom.com.br",
                    "isProxy": False,
                    "isp": "renovare telecom",
                },
                "severity": "INFO",
                "transaction": {"detail": {}, "id": "redacted", "type": "WEB"},
                "uuid": "redacted",
                "version": "0",
            },
        ),
        RuleTest(
            name="Okta internal event should be ignored",
            expected_result=False,
            mocks=[
                RuleMock(
                    object_name="get_string_set",
                    return_value='[\n    "123456",\n    "4.3.2.1",\n    "user_agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",\n    "CHROME",\n    "MacOS"\n]\n',
                ),
            ],
            log={
                "actor": {"alternateId": "admin", "displayName": "Bobert", "id": "unknown", "type": "User"},
                "authenticationContext": {"authenticationStep": 0, "externalSessionId": "123456789"},
                "client": {
                    "device": "Unknown",
                    "geographicalContext": {
                        "city": "Boardman",
                        "country": "United States",
                        "geolocation": {"lat": 45.8234, "lon": -119.7257},
                        "postalCode": "97818",
                        "state": "Oregon",
                    },
                    "id": "okta.b58d5b75-07d4-5f25-bf59-368a1261a405",
                    "ipAddress": "44.238.82.114",
                    "userAgent": {"browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "Okta-Integrations"},
                    "zone": "null",
                },
                "debugContext": {
                    "debugData": {
                        "loginResult": "VERIFICATION_ERROR",
                        "requestId": "redacted",
                        "requestUri": "redacted",
                        "threatSuspected": "false",
                        "url": "redacted",
                    },
                },
                "displayMessage": "User login to Okta",
                "eventType": "user.session.start",
                "legacyEventType": "core.user_auth.login_failed",
                "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"},
                "p_any_domain_names": ["rnvtelecom.com.br"],
                "p_any_ip_addresses": ["redacted"],
                "p_event_time": "redacted",
                "p_log_type": "Okta.SystemLog",
                "p_parse_time": "redacted",
                "p_row_id": "redacted",
                "p_source_id": "redacted",
                "p_source_label": "Okta",
                "published": "redacted",
                "request": {
                    "ipChain": [
                        {
                            "geographicalContext": {
                                "city": "Boardman",
                                "country": "United States",
                                "geolocation": {"lat": 45.8234, "lon": -119.7257},
                                "postalCode": "97818",
                                "state": "Oregon",
                            },
                            "ip": "44.238.82.114",
                            "version": "V4",
                        },
                    ],
                },
                "securityContext": {},
                "severity": "INFO",
                "transaction": {"detail": {}, "id": "redacted", "type": "WEB"},
                "uuid": "redacted",
                "version": "0",
            },
        ),
    ]
