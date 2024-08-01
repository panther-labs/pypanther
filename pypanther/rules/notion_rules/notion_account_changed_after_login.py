import time

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_notion_helpers import notion_alert_context
from pypanther.helpers.panther_oss_helpers import get_string_set, put_string_set

notion_account_changed_after_login_tests: list[RuleTest] = [
    RuleTest(
        name="Login event",
        expected_result=True,
        mocks=[RuleMock(object_name="put_string_set", return_value=True)],
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
        name="Email Changed Shortly After Login",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_string_set", return_value='[\n  "2023-06-12 21:40:28.690000000"\n]'),
            RuleMock(object_name="put_string_set", return_value=""),
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
                "type": "user.settings.login_method.email_updated",
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
        name="Password Changed Shortly After Login",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_string_set", return_value='[\n  "2023-06-12 21:40:28.690000000"\n]'),
            RuleMock(object_name="put_string_set", return_value=""),
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
                "type": "user.settings.login_method.password_updated",
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
        name="Password Added Shortly After Login",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_string_set", return_value='[\n  "2023-06-12 21:40:28.690000000"\n]'),
            RuleMock(object_name="put_string_set", return_value=""),
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
                "type": "user.settings.login_method.password_added",
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
        name="Password Removed Shortly After Login",
        expected_result=True,
        mocks=[
            RuleMock(object_name="get_string_set", return_value='[\n  "2023-06-12 21:40:28.690000000"\n]'),
            RuleMock(object_name="put_string_set", return_value=""),
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
                "type": "user.settings.login_method.password_removed",
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
        name="Email Changed Not Shortly After Login",
        expected_result=False,
        mocks=[
            RuleMock(object_name="get_string_set", return_value=False),
            RuleMock(object_name="put_string_set", return_value=""),
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
                "type": "user.settings.login_method.email_updated",
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
]


@panther_managed
class NotionAccountChangedAfterLogin(Rule):
    id = "Notion.AccountChangedAfterLogin-prototype"
    display_name = "Notion Account Changed Shortly After Login"
    log_types = [LogType.NOTION_AUDIT_LOGS]
    tags = ["Notion", "Identity & Access Management", "Persistence"]
    default_severity = Severity.MEDIUM
    default_description = "A Notion User logged in then changed their account details."
    default_runbook = (
        "Possible account takeover. Follow up with the Notion User to determine if this email change is genuine."
    )
    default_reference = "https://www.notion.so/help/account-settings"
    tests = notion_account_changed_after_login_tests
    # Length of time in minutes. If a user logs in, then changes their email within this many
    # minutes, raise an alert.
    DEFAULT_EMAIL_CHANGE_WINDOW_MINUTES = 10
    # Prefix for cached key. This ensures we don't accidently tamper with cached data from other
    # detections.
    CACHE_PREFIX = "Notion.AccountChangedAfterLogin"
    LOGIN_TS = None  # Default Value

    def rule(self, event):
        # If this is neither a login, nor an email/password change event, then exit
        allowed_event_types = {
            "user.login",
            "user.settings.login_method.email_updated",
            "user.settings.login_method.password_updated",
            "user.settings.login_method.password_added",
            "user.settings.login_method.password_removed",
        }
        if event.deep_walk("event", "type") not in allowed_event_types:
            return False
        # Global Variable Stuff
        # Extract user info
        userid = event.deep_walk("event", "actor", "id")
        cache_key = f"{self.CACHE_PREFIX}-{userid}"
        # If this is a login event, record it
        if event.deep_walk("event", "type") == "user.login":
            # Returning this as a bool allows us to write a unit test to determine if we cache login
            #   events when we're supposed to.
            # We'll save this for the alert context later
            return bool(
                put_string_set(
                    cache_key,
                    [str(event.get("p_event_time"))],
                    time.time() + self.DEFAULT_EMAIL_CHANGE_WINDOW_MINUTES * 60,
                ),
            )
        # If we made it here, then this is an account change event.
        # We first check if the user recently logged in:
        if last_login := get_string_set(cache_key, force_ttl_check=True):
            self.LOGIN_TS = list(last_login)[0]  # Save the last login timestamp for the alert context
            return True
        # If they haven't logged in recently, then return false
        return False

    def title(self, event):
        user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNOWN EMAIL")
        mins = self.DEFAULT_EMAIL_CHANGE_WINDOW_MINUTES
        action_taken = {
            "user.settings.login_method.email_updated": "changed their email",
            "user.settings.login_method.password_updated": "changed their password",
            "user.settings.login_method.password_added": "added a password to their account",
            "user.settings.login_method.password_removed": "removed the password from their account",
        }.get(event.deep_get("event", "type"), "altered their account info")
        return f"Notion User [{user_email}] {action_taken} within [{mins}] minutes of logging in."

    def alert_context(self, event):
        context = notion_alert_context(event)
        if self.LOGIN_TS:
            context["login_timestamp"] = self.LOGIN_TS
        return context
