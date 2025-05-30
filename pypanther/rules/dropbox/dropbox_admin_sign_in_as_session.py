from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DropboxAdminsigninasSession(Rule):
    default_description = "Alerts when an admin starts a sign-in-as session."
    display_name = "Dropbox Admin sign-in-as Session"
    default_reference = "https://help.dropbox.com/security/sign-in-as-user"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DROPBOX_TEAM_EVENT]
    id = "Dropbox.Admin.sign.in.as.Session-prototype"

    def rule(self, event):
        return event.deep_get("event_type", "_tag", default="") == "sign_in_as_session_start"

    def title(self, event):
        actor = event.deep_get("actor", "admin", "email", default="<ACTOR_NOT_FOUND>")
        target = event.deep_get("context", "email", default="<TARGET_NOT_FOUND>")
        return f"Dropbox: Admin [{actor}] started a sign-in-as session as user [{target}]."

    tests = [
        RuleTest(
            name="Other",
            expected_result=False,
            log={
                "actor": {
                    "_tag": "user",
                    "user": {
                        "_tag": "team_member",
                        "account_id": "dbid:AAACjvKy90uezyOiLRadIuCy66dK5d1vGGw",
                        "display_name": "Alice Bob",
                        "email": "alice.bob@company.com",
                        "team_member_id": "dbmid:AADSERs2cAsByYt8yQEDU4_qdNQiSdxgCl8",
                    },
                },
                "assets": [
                    {
                        ".tag": "file",
                        "display_name": "paper1.paper",
                        "file_id": "id:lUP4ZxMYmc4AAAAAAAAAaA",
                        "path": {
                            "contextual": "/pathtest/paper1.paper",
                            "namespace_relative": {
                                "is_shared_namespace": True,
                                "ns_id": "3590048721",
                                "relative_path": "/paper1.paper",
                            },
                        },
                    },
                ],
                "context": {
                    "_tag": "team_member",
                    "account_id": "dbid:AAACjvKy90uezyOiLRadIuCy66dK5d1vGGw",
                    "display_name": "Alice Bob",
                    "email": "alice.bob@company.com",
                    "team_member_id": "dbmid:AADSERs2cAsByYt8yQEDU4_qdNQiSdxgCl8",
                },
                "details": {
                    ".tag": "shared_content_add_member_details",
                    "shared_content_access_level": {".tag": "viewer"},
                },
                "event_category": {"_tag": "sharing"},
                "event_type": {
                    "_tag": "shared_content_add_member",
                    "description": "Added users and/or groups to shared file/folder",
                },
                "involve_non_team_member": True,
                "origin": {
                    "access_method": {
                        ".tag": "end_user",
                        "end_user": {".tag": "web", "session_id": "dbwsid:237034608707419186011941491025532848312"},
                    },
                    "geo_location": {"city": "Austin", "country": "US", "ip_address": "1.2.3.4", "region": "Texas"},
                },
                "p_any_emails": ["david.davidson@david.co", "alice.bob@company.com"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_any_usernames": ["Alice Bob", "david davidson"],
                "p_event_time": "2023-04-18 22:31:03",
                "p_log_type": "Dropbox.TeamEvent",
                "p_parse_time": "2023-04-18 22:32:46.967",
                "p_row_id": "fe2163f14b45f3c1b9a49fd31799a504",
                "p_schema_version": 0,
                "p_source_id": "b09c205e-42af-4933-8b18-b910985eb7fb",
                "p_source_label": "dropbox1",
                "participants": [
                    {
                        "user": {
                            "_tag": "non_team_member",
                            "account_id": "dbid:AABbWylBrTJ3Je-M37jeWShWuMAFHchEsKM",
                            "display_name": "david davidson",
                            "email": "david.davidson@david.co",
                        },
                    },
                ],
                "timestamp": "2023-04-18 22:31:03",
            },
        ),
        RuleTest(
            name="Sign-in-as Session",
            expected_result=True,
            log={
                "actor": {
                    "_tag": "admin",
                    "admin": {
                        "_tag": "team_member",
                        "account_id": "dbid:ABCDEFGHIJKLMONOPASQRST",
                        "display_name": "senvironment",
                        "email": "adminuser@company.com",
                        "team_member_id": "dbmid:AAAwgqIsigitfNAUAhsbxzQKtIPBM7uGAgg",
                    },
                },
                "context": {
                    "_tag": "team_member",
                    "account_id": "dbid:AAACjvKy90uezyOiLRadIuCy66dK5d1vGGw",
                    "display_name": "Alice Bob",
                    "email": "alice.bob@company.com",
                    "team_member_id": "dbmid:AADSERs2cAsByYt8yQEDU4_qdNQiSdxgCl8",
                },
                "details": {".tag": "sign_in_as_session_start_details"},
                "event_category": {"_tag": "logins"},
                "event_type": {"_tag": "sign_in_as_session_start", "description": "Started admin sign-in-as session"},
                "involve_non_team_member": False,
                "origin": {
                    "access_method": {
                        ".tag": "end_user",
                        "end_user": {".tag": "web", "session_id": "dbwsid:89515573818299775425117508904073133360"},
                    },
                    "geo_location": {"city": "Austin", "country": "US", "ip_address": "1.2.3.4", "region": "Texas"},
                },
                "p_any_emails": ["alice.bob@company.com", "adminuser@company.com"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_any_usernames": ["Alice Bob", "senvironment"],
                "p_event_time": "2023-04-19 19:20:02",
                "p_log_type": "Dropbox.TeamEvent",
                "p_parse_time": "2023-04-19 19:21:46.802",
                "p_row_id": "ca46ddc6518083b5a4cbbed517dc8f02",
                "p_schema_version": 0,
                "p_source_id": "b09c205e-42af-4933-8b18-b910985eb7fb",
                "p_source_label": "dropbox1",
                "timestamp": "2023-04-19 19:20:02",
            },
        ),
    ]
