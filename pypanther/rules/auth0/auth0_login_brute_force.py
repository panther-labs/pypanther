from panther_core import PantherEvent

from pypanther import Rule, Severity, panther_managed


@panther_managed
class Auth0BruteForce(Rule):
    display_name = "Auth0 Brute Force"
    default_severity = Severity.MEDIUM
    default_description = "Scheduled rule for brute force detection for Auth0 login or signup which looks for incidents of more than 10 incidents in one hour"
    default_reference = "https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes"
    inline_filters = [{"All": []}]
    scheduled_queries = ["Auth0 Brute Force Detection"]
    id = "Auth0.Brute.Force-prototype"

    def rule(self, event: PantherEvent) -> bool:  # pylint: disable=unused-argument
        return True

    def title(self, event: PantherEvent) -> str:
        total_incidents = event.get("total_incidents", 5)
        return f"Auth0 Brute Force detected: {total_incidents} attempts in the past hour"
