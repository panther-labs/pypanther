from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class DropboxLinkedTeamApplicationAdded(Rule):
    default_description = "An application was linked to your Dropbox Account"
    display_name = "Dropbox Linked Team Application Added"
    default_reference = "https://help.dropbox.com/integrations/app-integrations"
    default_runbook = "Ensure that the application is valid and not malicious. Verify that this is expected. If not, determine other actions taken by this user recently and reach out to the user. If the event involved a non-team member, consider disabling the user's access while investigating.\n"
    default_severity = Severity.LOW
    tags = ["dropbox"]
    log_types = [LogType.DROPBOX_TEAM_EVENT]
    id = "Dropbox.Linked.Team.Application.Added-prototype"

    def rule(self, event):
        return all(
            [
                event.deep_get("event_type", "_tag", default="") == "app_link_team",
                event.deep_get("event_type", "description", default="") == "Linked app for team",
            ],
        )

    def severity(self, event):
        # Anything involving non-team members should be High
        if event.get("involve_non_team_member", False):
            return "High"
        return "Low"

    def get_actor_type(self):
        # Admin who performed the action
        # Anonymous actor
        # Application that performed the action
        # Action performed by Dropbox
        # Action performed by reseller
        # User who performed the action
        return ("admin", "anonymous", "app", "dropbox", "reseller", "user")

    def title(self, event):
        # This will be one of the types returned by get_actor_type;
        # find the intersection and use that for the key
        actor_key = set(tuple(event.get("actor", {}).keys())).intersection(self.get_actor_type())
        if len(actor_key) == 1:
            display_name = event.deep_get("actor", tuple(actor_key)[0], "display_name", default="<Unknown>")
        else:
            # Explicitly use "<Unknown>" if we find any length of keys != 1
            display_name = "<Unknown>"
        return f"Dropbox Team Member Linked App by [{display_name}]"

    def user_details(self, event):
        details = {}
        for actor_key, actor_value in event.get("actor", {}).items():
            if actor_key == "_tag":
                continue
            for user_key, user_info in actor_value.items():
                if user_key in ("_tag", "display_name"):
                    continue
                details[user_key] = user_info
        return details

    def alert_context(self, event):
        additional_user_details = self.user_details(event)
        return {
            "additional_user_details": additional_user_details,
            "app_display_name": event.deep_get(
                "details",
                "app_info",
                "display_name",
                default="<Unknown app display name>",
            ),
            "ip_address": event.deep_get("origin", "geo_location", "ip_address", default="<Unknown IP address>"),
            "request_id": event.deep_get("origin", "access_method", "request_id", default="<Unknown request ID>"),
        }

    tests = [
        RuleTest(
            name="App linked for team is LOW severity",
            expected_result=True,
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
                    ".tag": "app_link_team_details",
                    "app_info": {
                        ".tag": "team_linked_app",
                        "app_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        "display_name": "dropbox-app-name",
                    },
                },
                "event_category": {"_tag": "apps"},
                "event_type": {"_tag": "app_link_team", "description": "Linked app for team"},
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
        RuleTest(
            name="A non-team linked event does not alert",
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
        RuleTest(
            name="App linked for team involving non-team member is HIGH severity",
            expected_result=True,
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
                    ".tag": "app_link_team_details",
                    "app_info": {
                        ".tag": "team_linked_app",
                        "app_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        "display_name": "dropbox-app-name",
                    },
                },
                "event_category": {"_tag": "apps"},
                "event_type": {"_tag": "app_link_team", "description": "Linked app for team"},
                "involve_non_team_member": True,
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
