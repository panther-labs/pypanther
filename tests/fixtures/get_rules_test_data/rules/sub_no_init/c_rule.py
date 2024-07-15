from pypanther import LogType, Rule, Severity


class CRule(Rule):
    default_severity = Severity.info
    id = "CRule"
    log_types = [LogType.Panther_Audit]

    def rule(self, event):
        return False
