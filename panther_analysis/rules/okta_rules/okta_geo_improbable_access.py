from typing import List
from panther_analysis.base import PantherRule, PantherRuleTest, Severity
from datetime import datetime, timedelta
from json import dumps, loads
from math import asin, cos, radians, sin, sqrt
from panther_analysis.helpers.panther_base_helpers import deep_get, okta_alert_context
from panther_detection_helpers.caching import get_string_set, put_string_set

okta_geographically_improbable_access_tests: List[PantherRuleTest] = [
    PantherRuleTest(Name="Non Login", ExpectedResult=False, Log={"eventType": "logout"}),
    PantherRuleTest(
        Name="Failed Login",
        ExpectedResult=False,
        Log={
            "actor": {
                "alternateId": "admin",
                "displayName": "unknown",
                "id": "unknown",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "unknown"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "city": "Dois Irmaos",
                    "country": "Brazil",
                    "geolocation": {"lat": -29.6116, "lon": -51.0933},
                    "postalCode": "93950",
                    "state": "Rio Grande do Sul",
                },
                "ipAddress": "redacted",
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
                }
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
                    }
                ]
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
    PantherRuleTest(
        Name="Incomplete GeoLocation info",
        ExpectedResult=False,
        Log={
            "actor": {
                "alternateId": "admin",
                "displayName": "unknown",
                "id": "unknown",
                "type": "User",
            },
            "authenticationContext": {"authenticationStep": 0, "externalSessionId": "unknown"},
            "client": {
                "device": "Computer",
                "geographicalContext": {
                    "country": "Brazil",
                    "geolocation": {"lat": -29.6116, "lon": -51.0933},
                    "postalCode": "93950",
                    "state": "Rio Grande do Sul",
                },
                "ipAddress": "redacted",
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
                }
            },
            "displayMessage": "User login to Okta",
            "eventType": "user.session.start",
            "legacyEventType": "core.user_auth.login_failed",
            "outcome": {"result": "SUCCESS"},
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
                            "country": "Brazil",
                            "geolocation": {"lat": -29.6116, "lon": -51.0933},
                            "postalCode": "93950",
                            "state": "Rio Grande do Sul",
                        },
                        "ip": "redacted",
                        "version": "V4",
                    }
                ]
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
]


class OktaGeographicallyImprobableAccess(PantherRule):
    RuleID = "Okta.GeographicallyImprobableAccess-prototype"
    DisplayName = "Geographically Improbable Okta Login - DEPRECATED"
    Enabled = False
    LogTypes = ["Okta.SystemLog"]
    Tags = ["Identity & Access Management", "Okta", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = Severity.High
    Description = (
        "A user has subsequent logins from two geographic locations that are very far apart"
    )
    Runbook = "Reach out to the user if needed to validate the activity, then lock the account"
    Reference = (
        "https://www.blinkops.com/blog/how-to-detect-and-remediate-okta-impossible-traveler-alerts"
    )
    SummaryAttributes = ["eventType", "severity", "p_any_ip_addresses", "p_any_domain_names"]
    Tests = okta_geographically_improbable_access_tests
    PANTHER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
    EVENT_CITY_TRACKING = {}
    # Taken from stack overflow user Michael0x2a: https://stackoverflow.com/a/19412565/6645635

    def rule(self, event):
        # Only evaluate successful logins
        if (
            event.get("eventType") != "user.session.start"
            or deep_get(event, "outcome", "result") == "FAILURE"
        ):
            return False
        new_login_stats = {
            "city": deep_get(event, "client", "geographicalContext", "city"),
            "lon": deep_get(event, "client", "geographicalContext", "geolocation", "lon"),
            "lat": deep_get(event, "client", "geographicalContext", "geolocation", "lat"),
        }
        # Bail out if we have a None value in set as it causes false positives
        if None in new_login_stats.values():
            return False
        # Generate a unique cache key for each user
        login_key = self.gen_key(event)
        # Retrieve the prior login info from the cache, if any
        last_login = get_string_set(login_key)
        # If we haven't seen this user login recently, store this login for future use and don't alert
        if not last_login:
            self.store_login_info(login_key, event)
            return False
        # Load the last login from the cache into an object we can compare
        old_login_stats = loads(last_login.pop())
        distance = self.haversine_distance(old_login_stats, new_login_stats)
        old_time = datetime.strptime(old_login_stats["time"][:26], self.PANTHER_TIME_FORMAT)
        new_time = datetime.strptime(event.get("p_event_time")[:26], self.PANTHER_TIME_FORMAT)
        time_delta = (new_time - old_time).total_seconds() / 3600  # seconds in an hour
        # Don't let time_delta be 0 (divide by zero error below)
        time_delta = time_delta or 0.0001
        # Calculate speed in Kilometers / Hour
        speed = distance / time_delta
        # Calculation is complete, so store the most recent login for the next check
        self.store_login_info(login_key, event)
        self.EVENT_CITY_TRACKING[event.get("p_row_id")] = {
            "new_city": new_login_stats.get("city", "<UNKNOWN_NEW_CITY>"),
            "old_city": old_login_stats.get("city", "<UNKNOWN_OLD_CITY>"),
        }
        return speed > 900  # Boeing 747 cruising speed

    def gen_key(self, event):
        return f"Okta.Login.GeographicallyImprobable{deep_get(event, 'actor', 'alternateId')}"

    def haversine_distance(self, grid_one, grid_two):
        # approximate radius of earth in km
        radius = 6371.0
        # Convert the grid elements to radians
        lon1, lat1, lon2, lat2 = map(
            radians, [grid_one["lon"], grid_one["lat"], grid_two["lon"], grid_two["lat"]]
        )
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        distance_a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        distance_c = 2 * asin(sqrt(distance_a))
        return radius * distance_c

    def store_login_info(self, key, event):
        # Map the user to the lon/lat and time of the most recent login
        put_string_set(
            key,
            [
                dumps(
                    {
                        "city": deep_get(event, "client", "geographicalContext", "city"),
                        "lon": deep_get(
                            event, "client", "geographicalContext", "geolocation", "lon"
                        ),
                        "lat": deep_get(
                            event, "client", "geographicalContext", "geolocation", "lat"
                        ),
                        "time": event.get("p_event_time"),
                    }
                )
            ],
            epoch_seconds=event.event_time_epoch() + timedelta(days=7).total_seconds(),
        )

    def title(self, event):
        # (Optional) Return a string which will be shown as the alert title.
        old_city = deep_get(
            self.EVENT_CITY_TRACKING.get(event.get("p_row_id")), "old_city", default="<NOT_STORED>"
        )
        new_city = deep_get(
            self.EVENT_CITY_TRACKING.get(event.get("p_row_id")),
            "new_city",
            default="<UNKNOWN_NEW_CITY>",
        )
        return f"Geographically improbable login for user [{deep_get(event, 'actor', 'alternateId')}] from [{old_city}]  to [{new_city}]"

    def dedup(self, event):
        # (Optional) Return a string which will de-duplicate similar alerts.
        return deep_get(event, "actor", "alternateId")

    def alert_context(self, event):
        context = okta_alert_context(event)
        context["old_city"] = deep_get(
            self.EVENT_CITY_TRACKING.get(event.get("p_row_id")), "old_city", default="<NOT_STORED>"
        )
        context["new_city"] = deep_get(
            self.EVENT_CITY_TRACKING.get(event.get("p_row_id")),
            "new_city",
            default="<UNKNOWN_NEW_CITY>",
        )
        return context
