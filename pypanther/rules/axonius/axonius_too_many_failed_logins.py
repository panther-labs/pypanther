import time

from panther_detection_helpers.caching import get_counter, increment_counter, reset_counter, set_key_expiration

from pypanther import LogType, Rule, RuleMock, RuleTest, Severity, panther_managed


@panther_managed
class AxoniusTooManyFailedLogins(Rule):
    id = "Axonius.TooManyFailedLogins-prototype"
    display_name = "Axonius login from Tor IP"
    log_types = [LogType.AXONIUS_ACTIVITY]
    tags = ["Axonius"]
    default_severity = Severity.MEDIUM
    default_description = "Detects an Axonius login from a malicious IP address"
    default_runbook = "Review the actions taken, check credentials/service user used and escalate."
    MAX_FAILS = 5
    TIME_WINDOW = 60 * 5
    CACHE_PREFIX = "axonius_too_many_failed_logins:"

    def rule(self, event):
        action = event.deep_get("event", "action", default="")
        status = event.deep_get("event", "params", "status", default="")
        username = event.deep_get("event", "user", default="")
        if status != "successful" and action == "AuditAction.LoginFrom":
            cache_key = f"{self.CACHE_PREFIX}{username}"
            count = int(get_counter(cache_key))
            if count > self.MAX_FAILS:
                reset_counter(cache_key)
                return True
            increment_counter(cache_key)
            set_key_expiration(cache_key, time.time() + self.TIME_WINDOW)
        return False

    def title(self, event):
        username = event.deep_get("event", "user", default="")
        return f"[Axonius] Too many failed Login from {username}"

    def alert_context(self, event):
        username = event.deep_get("event", "user", default="")
        ip_address = event.deep_get("event", "params", "ip", default="")
        action = event.deep_get("event", "action", default="")
        status = event.deep_get("event", "params", "status", default="")
        context = {"username": username, "ip_address": ip_address, "action": action, "status": status}
        return context

    tests = [
        RuleTest(
            name="Successful Login",
            expected_result=False,
            mocks=[
                RuleMock(object_name="get_counter", return_value="0"),
                RuleMock(object_name="increment_counter", return_value=True),
                RuleMock(object_name="set_key_expiration", return_value=True),
            ],
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
            name="One Failed Login",
            expected_result=False,
            mocks=[
                RuleMock(object_name="get_counter", return_value="0"),
                RuleMock(object_name="increment_counter", return_value=True),
                RuleMock(object_name="set_key_expiration", return_value=True),
            ],
            log={
                "event": {
                    "action": "AuditAction.LoginFrom",
                    "category": "AuditCategory.UserSession",
                    "params": {"ip": "1.2.3.4", "status": "failure"},
                    "type": "user",
                    "user": "denethor@lotr.com",
                },
                "source": "axonius",
                "time": 1752690986.344609,
            },
        ),
        RuleTest(
            name="Too Many Failed Login",
            expected_result=True,
            mocks=[
                RuleMock(object_name="get_counter", return_value="6"),
                RuleMock(object_name="increment_counter", return_value=True),
                RuleMock(object_name="set_key_expiration", return_value=True),
                RuleMock(object_name="reset_counter", return_value=True),
            ],
            log={
                "event": {
                    "action": "AuditAction.LoginFrom",
                    "category": "AuditCategory.UserSession",
                    "params": {"ip": "172.7.1.1", "status": "failure"},
                    "type": "user",
                    "user": "testr@axonius.com",
                },
                "source": "axonius",
                "time": 1752690986.344609,
            },
        ),
    ]
