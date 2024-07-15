from pypanther import LogType, Rule, Severity


class DRule(Rule):
    default_severity = Severity.info
    id = "DRule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False


class ERule(Rule):
    default_severity = Severity.info
    id = "ERule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False
