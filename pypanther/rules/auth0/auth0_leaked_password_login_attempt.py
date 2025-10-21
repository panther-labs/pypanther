from panther_core import PantherEvent

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class Auth0LeakedPasswordLoginAttempt(Rule):
    default_description = "Detect Auth0 Leaked Password Login Attempt"
    display_name = "Auth0 Leaked Password Login Attempt"
    default_severity = Severity.MEDIUM
    log_types = [LogType.AUTH0_EVENTS]
    id = "Auth0.Leaked.Password.Login.Attempt-prototype"

    def rule(self, event: PantherEvent) -> bool:
        return event.deep_get("data", "type") == "pwd_leak"

    def title(self, event: PantherEvent) -> str:
        ip_address = event.deep_get("data", "ip", default="NO_IP_FOUND")
        user_name = event.deep_get("data", "user_name", default="NO_USERNAME")
        event_title = "Someone behind the IP address {} attempted to login with a leaked password with username {}"
        return event_title.format(ip_address, user_name)

    tests = [
        RuleTest(
            name="FCOA Event",
            expected_result=True,
            log={
                "log_id": "90020251001053916537654000000000000001223372122475524001",
                "data": {
                    "date": "2025-10-01 05:39:16.467000000",
                    "type": "pwd_leak",
                    "description": "Someone behind the IP address: 2601:140:9702:ee80:0000:1f55:93a7:e970 attempted to login with a leaked password. A shield to prevent this action was enabled, further attempts are blocked.",
                    "connection": "Username-Password-Authentication",
                    "connection_id": "con_BvGURiLLdngYaT0D",
                    "client_id": "11Qpq1o8fbGgnZuFJnQCyjuC1ll8YFt0",
                    "ip": "2601:140:9702:ee80:9049:1f55:0000:e970",
                    "hostname": "auth.clientdomain.com",
                    "user_id": "",
                    "user_name": "geergo.michael@gmail.com",
                    "log_id": "90020251001053916537654000000000000001223372122475524001",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
                },
            },
        ),
    ]
