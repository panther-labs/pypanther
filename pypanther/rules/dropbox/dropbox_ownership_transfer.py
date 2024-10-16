import json
from unittest.mock import MagicMock

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed
from pypanther.helpers.config import config


@panther_managed
class DropboxOwnershipTransfer(Rule):
    default_description = "Dropbox ownership of a document or folder has been transferred."
    display_name = "Dropbox Document/Folder Ownership Transfer"
    default_reference = "https://help.dropbox.com/share/owner"
    default_severity = Severity.HIGH
    log_types = [LogType.DROPBOX_TEAM_EVENT]
    id = "Dropbox.Ownership.Transfer-prototype"
    DROPBOX_TRUSTED_OWNERSHIP_DOMAINS = config.DROPBOX_TRUSTED_OWNERSHIP_DOMAINS

    def rule(self, event):
        return "Transferred ownership " in event.deep_get("event_type", "description", default="")

    def title(self, event):
        actor = event.deep_get("actor", "user", "email", default="<EMAIL_NOT_FOUND>")
        previous_owner = event.deep_get("details", "previous_owner_email", default="<PREVIOUS_OWNER_NOT_FOUND>")
        new_owner = event.deep_get("details", "new_owner_email", default="<NEW_OWNER_NOT_FOUND>")
        assets = event.get("assets", [{}])
        asset = [a.get("display_name", "<ASSET_NOT_FOUND>") for a in assets]
        return f"Dropbox: [{actor}] transferred ownership of [{asset}]from [{previous_owner}] to [{new_owner}]."

    def severity(self, event):
        if isinstance(self.DROPBOX_TRUSTED_OWNERSHIP_DOMAINS, MagicMock):
            self.DROPBOX_TRUSTED_OWNERSHIP_DOMAINS = set(json.loads(self.DROPBOX_TRUSTED_OWNERSHIP_DOMAINS()))  # pylint: disable=not-callable
        new_owner = event.deep_get("details", "new_owner_email", default="<NEW_OWNER_NOT_FOUND>")
        if new_owner.split("@")[-1] not in self.DROPBOX_TRUSTED_OWNERSHIP_DOMAINS:
            return "HIGH"
        return "LOW"

    tests = [
        RuleTest(
            name="Folder Ownership Transfer to External",
            expected_result=True,
            log={
                "actor": {
                    "_tag": "user",
                    "user": {
                        "_tag": "team_member",
                        "account_id": "dbid:AAAAAAAAAAAAAAAAAAAAA",
                        "display_name": "Alice Bob",
                        "email": "alice.bob@company.io",
                        "team_member_id": "dbmid:BBBBBBBBBBBBBBBBBBBBBB",
                    },
                },
                "assets": [
                    {
                        ".tag": "folder",
                        "display_name": "test1",
                        "path": {
                            "contextual": "/Alice Bob/test1",
                            "namespace_relative": {"is_shared_namespace": True, "ns_id": "12345"},
                        },
                    },
                ],
                "context": {
                    "_tag": "team_member",
                    "account_id": "dbid:AAAAAAAAAAAAAAAAAAAAA",
                    "display_name": "Alice Bob",
                    "email": "alice.bob@company.io",
                    "team_member_id": "dbmid:BBBBBBBBBBBBBBBBBBBBBB",
                },
                "details": {
                    ".tag": "shared_folder_transfer_ownership_details",
                    "new_owner_email": "david.davidson@company.io",
                    "previous_owner_email": "alice.bob@company.io",
                },
                "event_category": {"_tag": "sharing"},
                "event_type": {
                    "_tag": "shared_folder_transfer_ownership",
                    "description": "Transferred ownership of shared folder to another member",
                },
                "involve_non_team_member": False,
                "origin": {
                    "access_method": {
                        ".tag": "end_user",
                        "end_user": {".tag": "web", "session_id": "dbwsid:237034608707419186011941491025532848312"},
                    },
                    "geo_location": {"city": "Austin", "country": "US", "ip_address": "1.2.3.4", "region": "Texas"},
                },
                "p_any_emails": ["alice.bob@company.io", "david.davidson@company.io"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_any_usernames": ["Alice Bob", "company"],
                "p_event_time": "2023-04-18 18:54:15",
                "p_log_type": "Dropbox.TeamEvent",
                "p_parse_time": "2023-04-18 18:56:47.418",
                "p_row_id": "0eb86fcfca9bb1cdce9defd217e1cd04",
                "p_schema_version": 0,
                "p_source_id": "b09c205e-42af-4933-8b18-b910985eb7fb",
                "p_source_label": "dropbox1",
                "participants": [
                    {
                        "user": {
                            "_tag": "team_member",
                            "account_id": "dbid:ABCD",
                            "display_name": "company",
                            "email": "david.davidson@company.io",
                            "team_member_id": "dbmid:DEFG",
                        },
                    },
                ],
                "timestamp": "2023-04-18 18:54:15",
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
            name="Folder Ownership Transfer to Internal",
            expected_result=True,
            mocks=[RuleMock(object_name="DROPBOX_TRUSTED_OWNERSHIP_DOMAINS", return_value='[\n    "example.com"\n]')],
            log={
                "actor": {
                    "_tag": "user",
                    "user": {
                        "_tag": "team_member",
                        "account_id": "dbid:AAAAAAAAAAAAAAAAAAAAA",
                        "display_name": "Alice Bob",
                        "email": "alice.bob@company.io",
                        "team_member_id": "dbmid:BBBBBBBBBBBBBBBBBBBBBB",
                    },
                },
                "assets": [
                    {
                        ".tag": "folder",
                        "display_name": "test1",
                        "path": {
                            "contextual": "/Alice Bob/test1",
                            "namespace_relative": {"is_shared_namespace": True, "ns_id": "12345"},
                        },
                    },
                ],
                "context": {
                    "_tag": "team_member",
                    "account_id": "dbid:AAAAAAAAAAAAAAAAAAAAA",
                    "display_name": "Alice Bob",
                    "email": "alice.bob@company.io",
                    "team_member_id": "dbmid:BBBBBBBBBBBBBBBBBBBBBB",
                },
                "details": {
                    ".tag": "shared_folder_transfer_ownership_details",
                    "new_owner_email": "david.davidson@example.com",
                    "previous_owner_email": "alice.bob@company.io",
                },
                "event_category": {"_tag": "sharing"},
                "event_type": {
                    "_tag": "shared_folder_transfer_ownership",
                    "description": "Transferred ownership of shared folder to another member",
                },
                "involve_non_team_member": False,
                "origin": {
                    "access_method": {
                        ".tag": "end_user",
                        "end_user": {".tag": "web", "session_id": "dbwsid:237034608707419186011941491025532848312"},
                    },
                    "geo_location": {"city": "Austin", "country": "US", "ip_address": "1.2.3.4", "region": "Texas"},
                },
                "p_any_emails": ["alice.bob@company.io", "david.davidson@example.com"],
                "p_any_ip_addresses": ["1.2.3.4"],
                "p_any_usernames": ["Alice Bob", "company"],
                "p_event_time": "2023-04-18 18:54:15",
                "p_log_type": "Dropbox.TeamEvent",
                "p_parse_time": "2023-04-18 18:56:47.418",
                "p_row_id": "0eb86fcfca9bb1cdce9defd217e1cd04",
                "p_schema_version": 0,
                "p_source_id": "b09c205e-42af-4933-8b18-b910985eb7fb",
                "p_source_label": "dropbox1",
                "participants": [
                    {
                        "user": {
                            "_tag": "team_member",
                            "account_id": "dbid:ABCD",
                            "display_name": "company",
                            "email": "david.davidson@example.com",
                            "team_member_id": "dbmid:DEFG",
                        },
                    },
                ],
                "timestamp": "2023-04-18 18:54:15",
            },
        ),
    ]
