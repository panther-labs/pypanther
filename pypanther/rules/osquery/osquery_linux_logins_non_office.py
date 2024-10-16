import ipaddress

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed


@panther_managed
class OsqueryLinuxLoginFromNonOffice(Rule):
    id = "Osquery.Linux.LoginFromNonOffice-prototype"
    display_name = "A Login from Outside the Corporate Office"
    enabled = False
    log_types = [LogType.OSQUERY_DIFFERENTIAL]
    tags = ["Configuration Required", "Osquery", "Linux", "Initial Access:Valid Accounts"]
    reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    default_severity = Severity.HIGH
    default_description = "A system has been logged into from a non approved IP space."
    default_runbook = "Analyze the host IP, and if possible, update allowlist or fix ACL."
    default_reference = "https://attack.mitre.org/techniques/T1078/"
    summary_attributes = ["name", "action", "p_any_ip_addresses", "p_any_domain_names"]
    # This is only an example network, but you can set it to whatever you'd like
    OFFICE_NETWORKS = [ipaddress.ip_network("192.168.1.100/32"), ipaddress.ip_network("192.168.1.200/32")]

    def _login_from_non_office_network(self, host):
        host_ipaddr = ipaddress.IPv4Address(host)
        non_office_logins = []
        for office_network in self.OFFICE_NETWORKS:
            non_office_logins.append(host_ipaddr in office_network)
        return not any(non_office_logins)

    def rule(self, event):
        if event.get("action") != "added":
            return False
        if "logged_in_users" in event.get("name"):
            # Only pay attention to users and not system-level accounts
            if event.deep_get("columns", "type") != "user":
                return False
        elif "last" in event.get("name"):
            pass
        else:
            # A query we don't care about
            return False
        host_ip = event.deep_get("columns", "host")
        return self._login_from_non_office_network(host_ip)

    def title(self, event):
        user = event.deep_get("columns", "user", default=event.deep_get("columns", "username"))
        return f"User [{(user if user else '<UNKNOWN_USER>')} has logged into production from a non-office network"

    tests = [
        RuleTest(
            name="Non-office network login (logged_in_users)",
            expected_result=True,
            log={
                "name": "pack/incident_response/logged_in_users",
                "action": "added",
                "columns": {"host": "10.0.3.1", "type": "user", "user": "ubuntu"},
            },
        ),
        RuleTest(
            name="Non-office network login (last)",
            expected_result=True,
            log={
                "name": "pack-incident_response-last",
                "action": "added",
                "columns": {
                    "host": "10.0.3.1",
                    "type": "8",
                    "username": "ubuntu",
                    "tty": "ttys008",
                    "pid": "648",
                    "time": "1587502574",
                },
            },
        ),
        RuleTest(
            name="Office network login",
            expected_result=False,
            log={
                "name": "pack-logged_in_users",
                "action": "added",
                "columns": {"host": "192.168.1.200", "user": "ubuntu"},
            },
        ),
    ]
