from datetime import datetime, timedelta
from json import dumps, loads
from typing import List

from panther_analysis.base import PantherRule, PantherRuleTest, RuleMock, Severity
from panther_analysis.helpers.panther_base_helpers import deep_get
from panther_analysis.helpers.panther_lookuptable_helpers import LookupTableMatches
from panther_analysis.helpers.panther_oss_helpers import (
    get_string_set,
    km_between_ipinfo_loc,
    put_string_set,
    resolve_timestamp_string,
)

notion_page_views_impossible_travel_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="Normal Page View",
        ExpectedResult=False,
        Mocks=[
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='[\n  {\n    "p_event_time": "2023-09-20T16:11:44.067000",\n    "source_ip": "192.168.100.100",\n    "city": "Minas Tirith",\n    "country": "Gondor",\n    "lat": "0.00000",\n    "lng": "0.00000",\n    "p_match": "192.168.100.100",\n    "postal_code": "55555",\n    "region": "Pellenor",\n    "region_code": "PL",\n    "timezone": "Middle Earth/Pellenor"\n  }\n]',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=False),
        ],
        Log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {
                    "page_audience": "shared_internally",
                    "page_name": "Notes: Council of Elrond",
                    "target": {
                        "page_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "type": "page_id",
                    },
                },
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-09-20 16:11:44.067000000",
                "type": "page.viewed",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Minas Tirith",
                        "country": "Gondor",
                        "lat": "0.00000",
                        "lng": "0.00000",
                        "p_match": "192.168.100.100",
                        "postal_code": "55555",
                        "region": "Pellenor",
                        "region_code": "PL",
                        "timezone": "Middle Earth/Pellenor",
                    }
                }
            },
            "p_event_time": "2023-09-20 16:11:44.067",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-09-20 16:18:27.542",
            "p_row_id": "52d6bafb77d1a7fb8bbdbfd81a0e",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion-Panther-Labs",
        },
    ),
    PantherRuleTest(
        Name="Evil Page View",
        ExpectedResult=True,
        Mocks=[
            RuleMock(
                ObjectName="get_string_set",
                ReturnValue='[\n  {\n    "p_event_time": "2023-09-20T15:11:44.067000",\n    "source_ip": "192.168.100.100",\n    "city": "Minas Tirith",\n    "country": "Gondor",\n    "lat": "0.00000",\n    "lng": "0.00000",\n    "p_match": "192.168.100.100",\n    "postal_code": "55555",\n    "region": "Pellenor",\n    "region_code": "PL",\n    "timezone": "Middle Earth/Pellenor"\n  }\n]',
            ),
            RuleMock(ObjectName="put_string_set", ReturnValue=False),
        ],
        Log={
            "event": {
                "actor": {
                    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    "object": "user",
                    "person": {"email": "aragorn.elessar@lotr.com"},
                    "type": "person",
                },
                "details": {
                    "page_audience": "shared_internally",
                    "page_name": "Notes: Council of Elrond",
                    "target": {
                        "page_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        "type": "page_id",
                    },
                },
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "ip_address": "192.168.100.100",
                "platform": "web",
                "timestamp": "2023-09-20 16:11:44.067000000",
                "type": "page.viewed",
                "workspace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            },
            "p_enrichment": {
                "ipinfo_location": {
                    "event.ip_address": {
                        "city": "Barad-Dur",
                        "lat": "100.00000",
                        "lng": "0.00000",
                        "country": "Mordor",
                        "postal_code": "55555",
                        "p_match": "192.168.100.100",
                        "region": "Mount Doom",
                        "region_code": "MD",
                        "timezone": "Middle Earth/Mordor",
                    }
                }
            },
            "p_event_time": "2023-09-20 16:11:44.067",
            "p_log_type": "Notion.AuditLogs",
            "p_parse_time": "2023-09-20 16:18:27.542",
            "p_row_id": "52d6bafb77d1a7fb8bbdbfd81a0e",
            "p_schema_version": 0,
            "p_source_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "p_source_label": "Notion-Panther-Labs",
        },
    ),
]


class NotionPageViewsImpossibleTravel(PantherRule):
    RuleID = "Notion.PageViews.ImpossibleTravel-prototype"
    DisplayName = "Notion Page View Impossible Travel DEPRECATED"
    Enabled = False
    LogTypes = ["Notion.AuditLogs"]
    Tags = [
        "Notion",
        "Identity & Access Management",
        "Login & Access Patterns",
        "Account Compromise",
    ]
    Severity = Severity.High
    Description = "A Notion User viewed a page from 2 locations simultaneously"
    DedupPeriodMinutes = 60
    Threshold = 1
    Runbook = "Possible account compromise. Review activity of this user."
    Reference = "https://raxis.com/blog/simultaneous-sessions/"
    Tests = notion_page_views_impossible_travel_tests

    def gen_key(self, event):
        """
        gen_key uses the data_model for the logtype to cache
        an entry that is specific to the Log Source ID

        The data_model needs to answer to "actor_user"
        """
        rule_name = deep_get(event, "p_source_label")
        actor = event.udm("actor_user")
        if None in [rule_name, actor]:
            return None
        return f"{rule_name.replace(' ', '')}..{actor}"

    def rule(self, event):
        # too-many-return-statements due to error checking
        # pylint: disable=global-statement,too-many-return-statements,too-complex
        self.EVENT_CITY_TRACKING = {}
        self.CACHE_KEY = None
        self.IS_VPN = False
        self.IS_APPLE_PRIVATE_RELAY = False
        # Only evaluate page views
        if event.deep_get("event", "type") != "page.viewed":
            return False
        p_event_datetime = resolve_timestamp_string(deep_get(event, "p_event_time"))
        if p_event_datetime is None:
            # we couldn't go from p_event_time to a datetime object
            # we need to do this in order to make later time comparisons generic
            return False
        new_login_stats = {
            "p_event_time": p_event_datetime.isoformat(),
            "source_ip": event.udm("source_ip"),
        }
        #
        src_ip_enrichments = LookupTableMatches().p_matches(event, event.udm("source_ip"))
        # stuff everything from ipinfo_location into the new_login_stats
        # new_login_stats is the value that we will cache for this key
        ipinfo_location = deep_get(src_ip_enrichments, "ipinfo_location")
        if ipinfo_location is None:
            return False
        new_login_stats.update(ipinfo_location)
        # Bail out if we have a None value in set as it causes false positives
        if None in new_login_stats.values():
            return False
        ## Check for VPN or Apple Private Relay
        ipinfo_privacy = deep_get(src_ip_enrichments, "ipinfo_privacy")
        if ipinfo_privacy is not None:
            ###  Do VPN/Apple private relay
            self.IS_APPLE_PRIVATE_RELAY = all(
                [
                    deep_get(ipinfo_privacy, "relay", default=False),
                    deep_get(ipinfo_privacy, "service", default="") == "Apple Private Relay",
                ]
            )
            # We've found that some places, like WeWork locations,
            #   have the VPN attribute set to true, but do not have a
            #   service name entry.
            # We have noticed VPN connections with commercial VPN
            #   offerings have the VPN attribute set to true, and
            #   do have a service name entry
            self.IS_VPN = all(
                [
                    deep_get(ipinfo_privacy, "vpn", default=False),
                    deep_get(ipinfo_privacy, "service", default="") != "",
                ]
            )
        if self.IS_VPN or self.IS_APPLE_PRIVATE_RELAY:
            new_login_stats.update(
                {
                    "is_vpn": f"{self.IS_VPN}",
                    "is_apple_priv_relay": f"{self.IS_APPLE_PRIVATE_RELAY}",
                    "service_name": f"{deep_get(ipinfo_privacy, 'service', default='<NO_SERVICE>')}",
                    "NOTE": "APPLE PRIVATE RELAY AND VPN LOGINS ARE NOT CACHED FOR COMPARISON",
                }
            )
        # Generate a unique cache key for each user per log type
        self.CACHE_KEY = self.gen_key(event)
        if self.CACHE_KEY is None:
            # We can't save without a cache key
            return False
        # Retrieve the prior login info from the cache, if any
        last_login = get_string_set(self.CACHE_KEY)
        # If we haven't seen this user login in the past 1 day,
        # store this login for future use and don't alert
        if not last_login and (not self.IS_APPLE_PRIVATE_RELAY) and (not self.IS_VPN):
            put_string_set(
                key=self.CACHE_KEY,
                val=[dumps(new_login_stats)],
                epoch_seconds=int((datetime.utcnow() + timedelta(days=1)).timestamp()),
            )
            return False
        # Load the last login from the cache into an object we can compare
        # str check is in place for unit test mocking
        if isinstance(last_login, str):
            tmp_last_login = loads(last_login)
            last_login = []
            for l_l in tmp_last_login:
                last_login.append(dumps(l_l))
        last_login_stats = loads(last_login.pop())
        distance = km_between_ipinfo_loc(last_login_stats, new_login_stats)
        old_time = resolve_timestamp_string(deep_get(last_login_stats, "p_event_time"))
        new_time = resolve_timestamp_string(deep_get(new_login_stats, "p_event_time"))
        time_delta = (new_time - old_time).total_seconds() / 3600  # seconds in an hour
        # Don't let time_delta be 0 (divide by zero error below)
        time_delta = time_delta or 0.0001
        # Calculate speed in Kilometers / Hour
        speed = distance / time_delta
        # Calculation is complete, write the current login to the cache
        put_string_set(
            key=self.CACHE_KEY,
            val=[dumps(new_login_stats)],
            epoch_seconds=int((datetime.utcnow() + timedelta(days=1)).timestamp()),
        )
        self.EVENT_CITY_TRACKING["previous"] = last_login_stats
        self.EVENT_CITY_TRACKING["current"] = new_login_stats
        self.EVENT_CITY_TRACKING["speed"] = int(speed)
        self.EVENT_CITY_TRACKING["speed_units"] = "km/h"
        self.EVENT_CITY_TRACKING["distance"] = int(distance)
        self.EVENT_CITY_TRACKING["distance_units"] = "km"
        return speed > 900  # Boeing 747 cruising speed

    def title(self, event):
        #
        log_source = deep_get(event, "p_source_label", default="<NO_SOURCE_LABEL>")
        old_city = deep_get(self.EVENT_CITY_TRACKING, "previous", "city", default="<NO_PREV_CITY>")
        new_city = deep_get(self.EVENT_CITY_TRACKING, "current", "city", default="<NO_PREV_CITY>")
        speed = deep_get(self.EVENT_CITY_TRACKING, "speed", default="<NO_SPEED>")
        distance = deep_get(self.EVENT_CITY_TRACKING, "distance", default="<NO_DISTANCE>")
        return f"Impossible Travel: [{event.udm('actor_user')}] in [{log_source}] went [{speed}] km/h for [{distance}] km between [{old_city}] and [{new_city}]"

    def dedup(self, event):  # pylint: disable=W0613
        return self.CACHE_KEY

    def alert_context(self, event):
        context = {"actor_user": event.udm("actor_user")}
        context.update(self.EVENT_CITY_TRACKING)
        return context

    def severity(self, _):
        if self.IS_VPN or self.IS_APPLE_PRIVATE_RELAY:
            return "INFO"
        # time = distance/speed
        distance = deep_get(self.EVENT_CITY_TRACKING, "distance", default=None)
        speed = deep_get(self.EVENT_CITY_TRACKING, "speed", default=None)
        if speed and distance:
            time = distance / speed
            # time of 0.1666 is 10 minutes
            if time < 0.1666 and distance < 50:
                # This is likely a GEOIP inaccuracy
                return "LOW"
        return "HIGH"
