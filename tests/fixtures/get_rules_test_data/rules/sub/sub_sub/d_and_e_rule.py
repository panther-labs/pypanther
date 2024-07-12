from pypanther import PantherLogType, PantherRule, PantherSeverity


class DRule(PantherRule):
    default_severity = PantherSeverity.info
    id_ = "DRule"
    log_types = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False


class ERule(PantherRule):
    default_severity = PantherSeverity.info
    id_ = "ERule"
    log_types = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
