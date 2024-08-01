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
