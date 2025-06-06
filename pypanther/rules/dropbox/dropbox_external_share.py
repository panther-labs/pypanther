import json
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class DropboxExternalShare(Rule):
    default_description = "Dropbox item shared externally"
    display_name = "Dropbox External Share"
    default_reference = "https://help.dropbox.com/share/share-outside-dropbox"
    default_severity = Severity.MEDIUM
    log_types = [LogType.DROPBOX_TEAM_EVENT]
    id = "Dropbox.External.Share-prototype"
    DROPBOX_ALLOWED_SHARE_DOMAINS = config.DROPBOX_ALLOWED_SHARE_DOMAINS

    def rule(self, event):
        if isinstance(self.DROPBOX_ALLOWED_SHARE_DOMAINS, MagicMock):
            self.DROPBOX_ALLOWED_SHARE_DOMAINS = set(json.loads(self.DROPBOX_ALLOWED_SHARE_DOMAINS()))  # pylint: disable=not-callable
        if event.deep_get("event_type", "_tag", default="") == "shared_content_add_member":
            participants = event.get("participants", [{}])
            for participant in participants:
                email = participant.get("user", {}).get("email", "")
                if email.split("@")[-1] not in self.DROPBOX_ALLOWED_SHARE_DOMAINS:
                    return True
        return False

    def title(self, event):
        actor = event.deep_get("actor", "user", "email", default="<ACTOR_NOT_FOUND>")
        assets = [e.get("display_name", "") for e in event.get("assets", [{}])]
        participants = event.get("participants", [{}])
        external_participants = []
        for participant in participants:
            email = participant.get("user", {}).get("email", "")
            if email.split("@")[-1] not in self.DROPBOX_ALLOWED_SHARE_DOMAINS:
                external_participants.append(email)
        return f"Dropbox: [{actor}] shared [{assets}] with external user [{external_participants}]."

    def alert_context(self, event):
        external_participants = []
        participants = event.get("participants", [{}])
        for participant in participants:
            email = participant.get("user", {}).get("email", "")
            if email.split("@")[-1] not in self.DROPBOX_ALLOWED_SHARE_DOMAINS:
                external_participants.append(email)
        return {"external_participants": external_participants}

    tests = [
        RuleTest(
            name="Domain in Allowlist",
            expected_result=False,
            mocks=[RuleMock(object_name="DROPBOX_ALLOWED_SHARE_DOMAINS", return_value='[\n    "example.com"\n]')],
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
                "p_any_emails": ["david.davidson@example.com", "alice.bob@company.com"],
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
                            "email": "david.davidson@example.com",
                        },
                    },
                ],
                "timestamp": "2023-04-18 22:31:03",
            },
        ),
        RuleTest(
            name="external share",
            expected_result=True,
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
    ]
