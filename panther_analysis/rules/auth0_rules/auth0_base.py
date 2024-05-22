from panther_analysis.base import PantherRule, Severity


class Auth0Rule(PantherRule):
    RuleID = "Auth0Rule"
    Severity = Severity.Info
    Enabled = True
    LogTypes = ["Auth0.Events"]

    def alert_context(self, event):
        alert_context = {}
        alert_context["actor"] = event.deep_get(
            "data", "details", "request", "auth", "user", default="<NO_ACTOR_FOUND>"
        )
        alert_context["action"] = event.deep_get("data", "description", default="<NO_ACTION_FOUND>")
        return alert_context

    def is_auth0_config_event(self, event):
        channel = event.deep_get("data", "details", "request", "channel", default="")
        return channel == "https://manage.auth0.com/"
