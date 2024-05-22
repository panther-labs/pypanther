from panther_analysis.base import PantherRule, Severity


class Auth0Rule(PantherRule):
    RuleID = "Auth0.Base-prototype"
    Severity = Severity.Info
    Enabled = True
    LogTypes = ["Auth0.Events"]

    def alert_context(self, event):
        a_c = {}
        a_c["actor"] = event.deep_get(
            "data", "details", "request", "auth", "user", default="<NO_ACTOR_FOUND>"
        )
        a_c["action"] = event.deep_get("data", "description", default="<NO_ACTION_FOUND>")
        return a_c

    def is_auth0_config_event(self, event):
        channel = event.deep_get("data", "details", "request", "channel", default="")
        return channel == "https://manage.auth0.com/"
