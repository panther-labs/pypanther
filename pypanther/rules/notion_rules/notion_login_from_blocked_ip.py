from pypanther import LogType, Rule, RuleMock, RuleTest, Severity
from pypanther.helpers.panther_notion_helpers import notion_alert_context


class NotionLoginFromBlockedIP(Rule):
    id_ = "Notion.LoginFromBlockedIP-prototype"
    display_name = "Notion Login From Blocked IP"
    enabled = False
    log_types = [LogType.Notion_AuditLogs]
    tags = [
        "Notion",
        "Network Security Monitoring",
        "Malicious Connections",
        "Configuration Required",
    ]
    default_severity = Severity.medium
    default_description = "A user attempted to access Notion from a blocked IP address. Note: before deployinh, make sure to add Rule Filters checking if event.ip_address is in a certain CIDR range(s)."
    default_runbook = (
        "Confirm with user if the login was legitimate. If so, determine why the IP is blocked."
    )
    default_reference = "https://www.notion.so/help/allowlist-ip"

    def rule(self, event):
        # Users can specify inline-filters to permit rules based on IPs
        return event.deep_get("event", "type", default="<NO_EVENT_TYPE_FOUND>") == "user.login"

    def title(self, event):
        user = event.deep_get("event", "actor", "person", "email", default="<NO_USER_FOUND>")
        ip_addr = event.deep_get("event", "ip_address", default="<UNKNOWN IP>")
        return f"Notion User [{user}] attempted to login from a blocked IP: [{ip_addr}]."

    def alert_context(self, event):
        return notion_alert_context(event)
