import datetime
import json
import time

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_ipinfo_helpers import IPInfoLocation
from pypanther.helpers.panther_notion_helpers import notion_alert_context
from pypanther.helpers.panther_oss_helpers import get_dictionary, put_dictionary

notion_login_from_new_location_tests: list[RuleTest] = [
    RuleTest(
        name="Login from normal location",
        expected_result=False,
        mocks=[
            RuleMock(object_name="get_dictionary", return_value='{ "Minas Tirith_Pellenor_Gondor": 1686542031 }'),
            RuleMock(object_name="put_dictionary", return_value=False),
        ],
        log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {"authType": "email"},
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-06-12 21:40:28.690000000",
                "type": "user.login",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Minas Tirith",
                        "lat": "0.00000",
                        "lng": "0.00000",
                        "country": "Gondor",
                        "postal_code": "55555",
                        "region": "Pellenor",
                        "region_code": "PL",
                        "timezone": "Middle Earth/Pellenor",
                    },
                },
            },
            "p_event_time": "2023-06-12 21:40:28.690000000",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-06-12 22:53:51.602223297",
            "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion Logs",
        },
    ),
    RuleTest(
        name="No previous recorded login",
        expected_result=False,
        mocks=[
            RuleMock(object_name="get_dictionary", return_value=""),
            RuleMock(object_name="put_dictionary", return_value=False),
        ],
        log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {"authType": "email"},
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-06-12 21:40:28.690000000",
                "type": "user.login",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Minas Tirith",
                        "lat": "0.00000",
                        "lng": "0.00000",
                        "country": "Gondor",
                        "postal_code": "55555",
                        "region": "Pellenor",
                        "region_code": "PL",
                        "timezone": "Middle Earth/Pellenor",
                    },
                },
            },
            "p_event_time": "2023-06-12 21:40:28.690000000",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-06-12 22:53:51.602223297",
            "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion Logs",
        },
    ),
    RuleTest(
        name="Login from different location",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_dictionary", return_value='{ "Minas Tirith_Pellenor_Gondor": 1686542031 }'),
            RuleMock(object_name="put_dictionary", return_value=False),
        ],
        log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {"authType": "email"},
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-06-12 21:40:28.690000000",
                "type": "user.login",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Barad-Dur",
                        "lat": "0.00000",
                        "lng": "0.00000",
                        "country": "Mordor",
                        "postal_code": "55555",
                        "region": "Mount Doom",
                        "region_code": "MD",
                        "timezone": "Middle Earth/Mordor",
                    },
                },
            },
            "p_event_time": "2023-06-12 21:40:28.690000000",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-06-12 22:53:51.602223297",
            "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion Logs",
        },
    ),
    RuleTest(
        name="Missing enrichment",
        expected_result=False,
        log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {"authType": "email"},
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-06-12 21:40:28.690000000",
                "type": "user.login",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {},
            "p_event_time": "2023-06-12 21:40:28.690000000",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-06-12 22:53:51.602223297",
            "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion Logs",
        },
    ),
    RuleTest(
        name="Unrelated event",
        expected_result=False,
        log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {"authType": "email"},
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-06-12 21:40:28.690000000",
                "type": "page.viewed",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Barad-Dur",
                        "lat": "0.00000",
                        "lng": "0.00000",
                        "country": "Mordor",
                        "postal_code": "55555",
                        "region": "Mount Doom",
                        "region_code": "MD",
                        "timezone": "Middle Earth/Mordor",
                    },
                },
            },
            "p_event_time": "2023-06-12 21:40:28.690000000",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-06-12 22:53:51.602223297",
            "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion Logs",
        },
    ),
    RuleTest(
        name="Login from different location - no region",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_dictionary", return_value='{ "Minas Tirith_Pellenor_Gondor": 1686542031 }'),
            RuleMock(object_name="put_dictionary", return_value=False),
        ],
        log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {"authType": "email"},
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-06-12 21:40:28.690000000",
                "type": "user.login",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Barad-Dur",
                        "lat": "0.00000",
                        "lng": "0.00000",
                        "country": "Mordor",
                        "postal_code": "55555",
                        "region_code": "MD",
                        "timezone": "Middle Earth/Mordor",
                    },
                },
            },
            "p_event_time": "2023-06-12 21:40:28.690000000",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-06-12 22:53:51.602223297",
            "p_row_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion Logs",
        },
    ),
]


@panther_managed
class NotionLoginFromNewLocation(Rule):
    id = "Notion.LoginFromNewLocation-prototype"
    display_name = "Notion Login from New Location"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Identity & Access Management", "Login & Access Patterns"]
    default_severity = Severity.MEDIUM
    default_description = "A Notion User logged in from a new location."
    default_runbook = "Possible account takeover. Follow up with the Notion User to determine if this login is genuine."
    default_reference = "https://ipinfo.io/products/ip-geolocation-api"
    tests = notion_login_from_new_location_tests
    # How long (in seconds) to keep previous login locations in cached memory
    DEFAULT_CACHE_PERIOD = 2419200

    def rule(self, event):
        # Only focused on login events
        if event.deep_walk("event", "type") != "user.login":
            return False
        # Get the user's location, via IPInfo
        # Return False if we have no location information
        if "ipinfo_location" not in event.get("p_enrichment", {}):
            return False
        self.IPINFO_LOC = IPInfoLocation(event)
        path_to_ip = "event.ip_address"
        city = self.IPINFO_LOC.city(path_to_ip) or ""
        region = self.IPINFO_LOC.region(path_to_ip) or ""
        country = self.IPINFO_LOC.country(path_to_ip) or ""
        loc_string = "_".join((city, region, country))
        # Store the login location. The premise is to create a new entry for each combimation of user
        # and location, and then have those records persist for some length of time (4 weeks by
        # default).
        # Store the login location. Here, we use Panther's cache to store a dictionary, using the
        #   user's unique ID to ensure it hold data unique to them. In this dictionary, we'll use the
        #   location strings (loc_string) as the key, and the values will be the timestamp of the last
        #   recorded login from that location.
        user = event.deep_walk("event", "actor", "id")
        cache = get_dictionary(user) or {}
        # If this is a unit test, convert cache from string
        if isinstance(cache, str):
            cache = json.loads(cache)
        # -- Step 1: Record this login.
        new_cache = cache.copy()
        new_cache[loc_string] = time.time()
        put_dictionary(user, new_cache)
        # -- Step 2: Determine if we shoul raise an alert.
        if not cache:
            # User hasn't been recorded logging in before. Since this is their first login, we don't
            #   have a baseline to know if it's unusual, so we won't raise an alert.
            return False
        if self.is_recent_login(cache, loc_string, event.get("p_parse_time")):
            # User has logged in from this location in the recent past. No need to raise an alert.
            return False
        # User has NOT logged in from this location in the recent past - we should trigger an alert!
        return True

    def title(self, event):
        path_to_ip = "event.ip_address"
        city = self.IPINFO_LOC.city(path_to_ip)
        region = self.IPINFO_LOC.region(path_to_ip)
        country = self.IPINFO_LOC.country(path_to_ip)
        user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNWON_EMAIL")
        return f"Notion [{user_email}] logged in from a new location: {city}, {region}, {country}."

    def alert_context(self, event):
        path_to_ip = "event.ip_address"
        city = self.IPINFO_LOC.city(path_to_ip)
        region = self.IPINFO_LOC.region(path_to_ip)
        country = self.IPINFO_LOC.country(path_to_ip)
        user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNWON_EMAIL")
        context = notion_alert_context(event)
        context["user_email"] = user_email
        context["location"] = {"city": city, "region": region, "country": country}
        return context

    def is_recent_login(self, cache: dict, loc_string: str, parse_time: str) -> bool:
        # Use p_parse_time to calculate current timestamp, so that unit tests work.
        now = time.mktime(
            datetime.datetime.fromisoformat(parse_time[:23]).timetuple(),
        )  # location was previously recorded
        # last recorded login is recent
        return loc_string in cache and cache[loc_string] > now - self.DEFAULT_CACHE_PERIOD
