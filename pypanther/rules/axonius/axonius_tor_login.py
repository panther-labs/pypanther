from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.tor import TorExitNodes


@panther_managed
class AxoniusTorLogin(Rule):
    id = "Axonius.TorLogin-prototype"
    display_name = "Axonius login from Tor IP"
    log_types = [LogType.AXONIUS_ACTIVITY]
    tags = ["Axonius", "Tor"]
    default_severity = Severity.MEDIUM
    default_description = "Detects an Axonius login from Tor IP address"
    default_runbook = "Review the actions taken, check credentials/service user used and escalate."

    def rule(self, event):
        action = event.deep_get("event", "action", default="")
        status = event.deep_get("event", "params", "status", default="")
        if status == "successful" and action == "AuditAction.LoginFrom":
            return TorExitNodes(event).has_exit_nodes()
        return False

    def title(self, event):
        username = event.deep_get("event", "user", default="")
        return f"[Axonius] Login from {username} Detected on a TOR IP Address"

    def alert_context(self, event):
        username = event.deep_get("event", "user", default="")
        ip_address = event.deep_get("event", "params", "ip", default="")
        action = event.deep_get("event", "action", default="")
        status = event.deep_get("event", "params", "status", default="")
        context = {"username": username, "ip_address": ip_address, "action": action, "status": status}
        return context

    tests = [
        RuleTest(
            name="Benign Login",
            expected_result=False,
            log={
                "event": {
                    "action": "AuditAction.LoginFrom",
                    "category": "AuditCategory.UserSession",
                    "params": {"ip": "1.2.3.4", "status": "successful"},
                    "type": "user",
                    "user": "denethor@lotr.com",
                },
                "source": "axonius",
                "time": 1752690986.344609,
            },
        ),
        RuleTest(
            name="TOR Successful Login",
            expected_result=True,
            log={
                "event": {
                    "action": "AuditAction.LoginFrom",
                    "category": "AuditCategory.UserSession",
                    "params": {"ip": "1.2.3.4", "status": "successful"},
                    "type": "user",
                    "user": "denethor@lotr.com",
                },
                "source": "axonius",
                "time": 1752690986.344609,
                "p_enrichment": {"tor_exit_nodes": True},
            },
        ),
        RuleTest(
            name="TOR Failed Login",
            expected_result=False,
            log={
                "event": {
                    "action": "AuditAction.LoginFrom",
                    "category": "AuditCategory.UserSession",
                    "params": {"ip": "172.7.1.1", "status": "fail"},
                    "type": "user",
                    "user": "testr@axonius.com",
                },
                "source": "axonius",
                "time": 1752690986.344609,
                "p_enrichment": {"tor_exit_nodes": True},
            },
        ),
    ]
