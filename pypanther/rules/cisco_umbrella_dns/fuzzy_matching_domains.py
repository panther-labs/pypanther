from difflib import SequenceMatcher

from pypanther import LogType, Rule, Severity, panther_managed


@panther_managed
class CiscoUmbrellaDNSFuzzyMatching(Rule):
    id = "CiscoUmbrella.DNS.FuzzyMatching-prototype"
    display_name = "Cisco Umbrella Domain Name Fuzzy Matching"
    enabled = False
    dedup_period_minutes = 15
    log_types = [LogType.CISCO_UMBRELLA_DNS]
    tags = ["Configuration Required", "DNS"]
    default_reference = "https://umbrella.cisco.com/blog/abcs-of-dns"
    default_severity = Severity.MEDIUM
    default_description = "Identify lookups to suspicious domains that could indicate a phishing attack."
    default_runbook = "Validate if your organization owns the domain, otherwise investigate the host that made the domain resolution.\n"
    DOMAIN = ""  # The domain to monitor for phishing, for example "google.com"
    # List all of your known-good domains here
    ALLOW_SET = {}
    SIMILARITY_RATIO = 0.7

    def rule(self, event):
        # Domains coming through umbrella end with a dot, such as google.com.
        domain = ".".join(event.get("domain").rstrip(".").split(".")[-2:]).lower()
        return (
            domain not in self.ALLOW_SET and SequenceMatcher(None, self.DOMAIN, domain).ratio() >= self.SIMILARITY_RATIO
        )

    def title(self, event):
        return f"Suspicious DNS resolution to {event.get('domain')}"
