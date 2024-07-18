from pypanther import LogType, Rule, Severity


class ARule(Rule):
    default_severity = Severity.INFO
    id = "ARule"
    log_types = [LogType.PANTHER_AUDIT]

    def rule(self, event):
        return False
