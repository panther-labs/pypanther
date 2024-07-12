from pypanther import LogType, Rule, Severity


class DRule(Rule):
    default_severity = Severity.info
    id_ = "DRule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False


class ERule(Rule):
    default_severity = Severity.info
    id_ = "ERule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False
