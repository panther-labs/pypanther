from pypanther import LogType, Rule, Severity


class DRule(Rule):
    default_severity = Severity.INFO
    id = "DRule"
    log_types = [LogType.PANTHER_AUDIT]

    def rule(self, event):
        return False


class ERule(Rule):
    default_severity = Severity.INFO
    id = "ERule"
    log_types = [LogType.PANTHER_AUDIT]

    def rule(self, event):
        return False
