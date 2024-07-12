from pypanther import PantherLogType, PantherRule, PantherSeverity


class ARule(PantherRule):
    default_severity = PantherSeverity.info
    id_ = "ARule"
    log_types = [PantherLogType.Panther_Audit]

    def rule(self, event):
        return False
