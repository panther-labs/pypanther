from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class Auth0Limits(Rule):
    default_description = "Detect Auth0 Limit Logs"
    display_name = "Auth0 Limit Detections"
    default_severity = Severity.MEDIUM
    log_types = [LogType.AUTH0_EVENTS]
    id = "Auth0.Limits-prototype"
    SUSPICIOUS_EVENT_TYPES = (
        "api_limit",
        "gd_otp_rate_limit_exceed",
        "gd_recovery_rate_limit_exceed",
        "limit_delegation",
        "limit_mu",
        "limit_sul",
        "limit_wc",
    )
    EVENT_TITLES = (
        "The maximum number of requests to the Authentication or Management APIs has been reached for {}",
        "Too many MFA failures occured for {}",
        "{} has entered a wrong recovery code too many times",
        "Rate limit exceeded to the delegation token endpoint by {}",
        "{} IP address is blocked because it attempted too many sign-ups or failed logins: {}",
        "{} is temporarily blocked from logging in because they reached the maximum logins from {}",
        "{} IP address is blocked because it reached the maximum failed login attempts into a single account: {}",
    )

    def rule(self, event: PantherEvent) -> bool:
        return event.deep_get("data", "type") in self.SUSPICIOUS_EVENT_TYPES

    def title(self, event: PantherEvent) -> str:
        limit_mu_index = self.SUSPICIOUS_EVENT_TYPES.index("limit_mu")
        limit_sul_index = self.SUSPICIOUS_EVENT_TYPES.index("limit_sul")
        limit_wc_index = self.SUSPICIOUS_EVENT_TYPES.index("limit_wc")
        event_type = event.deep_get("data", "type")
        event_index = self.SUSPICIOUS_EVENT_TYPES.index(event_type)
        event_title = self.EVENT_TITLES[event_index]
        # limit_mu or limit_wc
        if event_index in {limit_mu_index, limit_wc_index}:
            ip_address = event.deep_get("data", "ip", default="NO_IP_FOUND")
            username = event.deep_get("data", "user_name", default="NO_USER_FOUND")
            return event_title.format(ip_address, username)
        # limit_sul
        if event_index == limit_sul_index:
            ip_address = event.deep_get("data", "ip", default="NO_IP_FOUND")
            username = event.deep_get("data", "user_name", default="NO_USER_FOUND")
            return event_title.format(username, ip_address)
        # other cases have only "user_name" field in their titles
        username = event.deep_get("data", "user_name", default="NO_USER_FOUND")
        return event_title.format(username)

    tests = [
        RuleTest(
            name="Limit WC Event",
            expected_result=True,
            log={
                "log_id": "90020250930212349746493000000000000001223372122436618809",
                "data": {
                    "date": "2025-09-30 21:23:49.689000000",
                    "type": "limit_wc",
                    "description": "User (john@justice.org) attempted 10 consecutive logins unsuccessfully. Brute force protection is enabled for this connection, further attempts are blocked from this IP address for this user.",
                    "connection": "Username-Password-Authentication",
                    "connection_id": "con_BvGURiLLdngYaT0D",
                    "client_id": "11Qpq1o8fbGgnZuFJnQCyjuC1ll8YFt0",
                    "ip": "1.2.3.4",
                    "hostname": "auth.clientdomain.com",
                    "user_id": "",
                    "user_name": "john@justice.org",
                    "log_id": "90020250930212349746493000000000000001223372122436618809",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
                },
            },
        ),
    ]
