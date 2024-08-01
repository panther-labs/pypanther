from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import deep_get

dropbox_user_disabled2_fa_tests: list[RuleTest] = [
    RuleTest(
        name="2FA Disabled",
        expected_result=True,
        log={
            "actor": {
                "_tag": "user",
                "user": {
                    "_tag": "team_member",
                    "account_id": "dbid:AAAAAAAAAAAAAAAA",
                    "display_name": "Alice Bob",
                    "email": "alice.bob@company.io",
                    "team_member_id": "dbmid:AABBBBBBBBBBBBBBBBBBBBBBB",
                },
            },
            "context": {
                "_tag": "team_member",
                "account_id": "dbid:AAAAAAAAAAAAAAAA",
                "display_name": "Alice Bob",
                "email": "alice.bob@company.io",
                "team_member_id": "dbmid:AABBBBBBBBBBBBBBBBBBBBBBB",
            },
            "details": {
                ".tag": "tfa_change_status_details",
                "new_value": {".tag": "disabled"},
                "previous_value": {".tag": "authenticator"},
                "used_rescue_code": True,
            },
            "event_category": {"_tag": "tfa"},
            "event_type": {
                "_tag": "tfa_change_status",
                "description": "Enabled/disabled/changed two-step verification setting",
            },
            "involve_non_team_member": False,
            "origin": {
                "access_method": {
                    ".tag": "end_user",
                    "end_user": {".tag": "web", "session_id": "dbwsid:237034608707419186011941491025532848312"},
                },
                "geo_location": {"city": "Austin", "country": "US", "ip_address": "1.2.3.4", "region": "Texas"},
            },
            "p_any_emails": ["alice.bob@company.io"],
            "p_any_ip_addresses": ["1.2.3.4"],
            "p_any_usernames": ["Alice Bob"],
            "p_event_time": "2023-04-18 18:16:27",
            "p_log_type": "Dropbox.TeamEvent",
            "p_parse_time": "2023-04-18 18:18:46.808",
            "p_row_id": "0eb86fcfca9bb1cdce9defd217b8ac03",
            "p_schema_version": 0,
            "p_source_id": "b09c205e-42af-4933-8b18-b910985eb7fb",
            "p_source_label": "dropbox1",
            "timestamp": "2023-04-18 18:16:27",
        },
    ),
    RuleTest(
        name="Other",
        expected_result=False,
        log={
            "actor": {
                "_tag": "user",
                "user": {
                    "_tag": "team_member",
                    "account_id": "dbid:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "display_name": "user_name",
                    "email": "user@domain.com",
                    "team_member_id": "dbmid:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                },
            },
            "context": {"_tag": "team"},
            "details": {
                ".tag": "app_link_member_details",
                "app_info": {
                    ".tag": "member_linked_app",
                    "app_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "display_name": "personal-dropbox-app-name",
                },
            },
            "event_category": {"_tag": "apps"},
            "event_type": {"_tag": "app_link_member", "description": "Linked app for member"},
            "involve_non_team_member": False,
            "origin": {
                "access_method": {".tag": "api", "request_id": "dbarod:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
                "geo_location": {
                    "city": "Los Angeles",
                    "country": "US",
                    "ip_address": "1.2.3.4",
                    "region": "California",
                },
            },
            "timestamp": "2023-02-16 20:39:34",
        },
    ),
]


@panther_managed
class DropboxUserDisabled2FA(Rule):
    default_description = "Dropbox user has disabled 2fa login"
    display_name = "Dropbox User Disabled 2FA"
    default_reference = "https://help.dropbox.com/account-access/enable-two-step-verification"
    default_severity = Severity.LOW
    log_types = [LogType.DROPBOX_TEAM_EVENT]
    id = "Dropbox.User.Disabled.2FA-prototype"
    tests = dropbox_user_disabled2_fa_tests

    def rule(self, event):
        return all(
            [
                deep_get(event, "details", ".tag", default="") == "tfa_change_status_details",
                deep_get(event, "details", "new_value", ".tag") == "disabled",
            ],
        )

    def title(self, event):
        actor = deep_get(event, "actor", "user", "email", default="<EMAIL_NOT_FOUND>")
        target = deep_get(event, "context", "email", default="<TARGET_NOT_FOUND>")
        return f"Dropbox: [{actor}] disabled 2FA for [{target}]."
