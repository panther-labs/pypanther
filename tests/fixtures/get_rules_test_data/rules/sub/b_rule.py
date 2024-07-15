from pypanther import LogType, Rule, Severity


class BRule(Rule):
    default_severity = Severity.INFO
    id = "BRule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False
