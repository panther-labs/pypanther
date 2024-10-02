from pypanther import LogType, Rule, Severity, panther_managed


@panther_managed
class AWSConsoleLogin(Rule):
    id = "AWS.Console.Login-prototype"
    display_name = "AWS Console Login"
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.INFO
    create_alert = False

    def rule(self, event):
        return event.get("eventName") == "ConsoleLogin"

    def alert_context(self, event):
        context = {}
        context["ip_and_username"] = event.get("sourceIPAddress", "<MISSING_SOURCE_IP>") + event.deep_get(
            "userIdentity",
            "userName",
            default="<MISSING_USER_NAME>",
        )
        return context
