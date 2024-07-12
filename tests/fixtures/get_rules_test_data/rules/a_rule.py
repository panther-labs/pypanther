from pypanther import LogType, Rule, Severity


class ARule(Rule):
    default_severity = Severity.info
    id_ = "ARule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False
