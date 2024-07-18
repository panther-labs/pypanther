from pypanther import LogType, Rule, Severity


class BRule(Rule):
    default_severity = Severity.INFO
    id = "BRule"
    log_types = [LogType.PANTHER_AUDIT]

    def rule(self, event):
        return False
