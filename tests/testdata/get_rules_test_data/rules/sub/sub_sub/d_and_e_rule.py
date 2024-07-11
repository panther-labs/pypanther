from pypanther import PantherSeverity, PantherRule, PantherLogType


class DRule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "DRule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False


class ERule(PantherRule):
    Severity = PantherSeverity.Info
    RuleID = "ERule"
    LogTypes = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
