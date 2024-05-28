from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from pypanther.base import PantherRule, PantherRuleTest, PantherSeverity
from pypanther.helpers.panther_base_helpers import (
    golang_nanotime_to_python_datetime,
    panther_nanotime_to_python_datetime,
)
from pypanther.log_types import LogType

teleport_long_lived_certs_tests: List[PantherRuleTest] = [
    PantherRuleTest(
        Name="A certificate was created for the default period of 1 hour",
        ExpectedResult=False,
        Log={
            "cert_type": "user",
            "cluster_name": "teleport.example.com",
            "code": "TC000I",
            "ei": 0,
            "event": "cert.create",
            "time": "2023-09-17 21:00:00.000000",
            "identity": {
                "disallow_reissue": True,
                "expires": "2023-09-17T22:00:00.444444428Z",
                "impersonator": "bot-application",
                "kubernetes_cluster": "staging",
                "kubernetes_groups": ["application"],
                "logins": [
                    "-teleport-nologin-88888888-4444-4444-4444-222222222222",
                    "-teleport-internal-join",
                ],
                "prev_identity_expires": "0001-01-01T00:00:00Z",
                "roles": ["application"],
                "route_to_cluster": "teleport.example.com",
                "teleport_cluster": "teleport.example.com",
                "traits": {},
                "user": "bot-application",
            },
            "uid": "88888888-4444-4444-4444-222222222222",
        },
    ),
    PantherRuleTest(
        Name="A certificate was created for longer than the default period of 1 hour",
        ExpectedResult=True,
        Log={
            "cert_type": "user",
            "cluster_name": "teleport.example.com",
            "code": "TC000I",
            "ei": 0,
            "event": "cert.create",
            "time": "2023-09-17 21:00:00.000000",
            "identity": {
                "disallow_reissue": True,
                "expires": "2043-09-17T22:00:00.444444428Z",
                "impersonator": "bot-application",
                "kubernetes_cluster": "staging",
                "kubernetes_groups": ["application"],
                "logins": [
                    "-teleport-nologin-88888888-4444-4444-4444-222222222222",
                    "-teleport-internal-join",
                ],
                "prev_identity_expires": "0001-01-01T00:00:00Z",
                "roles": ["application"],
                "route_to_cluster": "teleport.example.com",
                "teleport_cluster": "teleport.example.com",
                "traits": {},
                "user": "bot-application",
            },
            "uid": "88888888-4444-4444-4444-222222222222",
        },
    ),
]


class TeleportLongLivedCerts(PantherRule):
    RuleID = "Teleport.LongLivedCerts-prototype"
    DisplayName = "A long-lived cert was created"
    LogTypes = [LogType.Gravitational_TeleportAudit]
    Tags = ["Teleport"]
    Severity = PantherSeverity.Medium
    Description = "An unusually long-lived Teleport certificate was created"
    Reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    Reference = "https://goteleport.com/docs/management/admin/"
    Runbook = "Teleport certificates are usually issued for a short period of time. Alert if long-lived certificates were created.\n"
    SummaryAttributes = ["event", "code", "time", "identity"]
    Tests = teleport_long_lived_certs_tests
    PANTHER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
    # Tune this to be some Greatest Common Denominator of session TTLs for your
    # environment
    MAXIMUM_NORMAL_VALIDITY_INTERVAL = timedelta(hours=12)
    # To allow some time in between when a request is submitted and authorized
    # vs when the certificate actually gets generated. In practice, this is much
    # less than 5 seconds.
    ISSUANCE_GRACE_PERIOD = timedelta(seconds=5)
    # You can audit your logs in Panther to try and understand your role/validity
    # patterns from a known-good period of access.
    # A query example:
    # ```sql
    #  SELECT
    #     cluster_name,
    #     identity:roles,
    #     DATEDIFF('HOUR', time, identity:expires) AS validity
    #  FROM
    #     panther_logs.public.gravitational_teleportaudit
    #  WHERE
    #     p_occurs_between('2023-09-01 00:00:00','2023-10-06 21:00:00Z')
    #     AND event = 'cert.create'
    #  GROUP BY cluster_name, identity:roles, validity
    #  ORDER BY validity DESC
    # ```
    # A dictionary of:
    #  cluster names: to a dictionary of:
    #     role names: mapping to a tuple of:
    #        ( maximum usual validity, expiration datetime for this rule )
    # "teleport.example.com": {
    #     "example_role": (timedelta(hours=720), datetime(2023, 12, 01, 01, 02, 03)),
    #     "other_example_role": (timedelta(hours=720), datetime.max),
    # },
    CLUSTER_ROLE_MAX_VALIDITIES: Dict[str, Dict[str, Tuple[timedelta, datetime]]] = {}

    def rule(self, event):
        if not event.get("event") == "cert.create":
            return False
        max_validity = self.MAXIMUM_NORMAL_VALIDITY_INTERVAL + self.ISSUANCE_GRACE_PERIOD
        for role in event.deep_get("identity", "roles", default=[]):
            validity, expiration = self.CLUSTER_ROLE_MAX_VALIDITIES.get(
                event.get("cluster_name"), {}
            ).get(role, (None, None))
            if validity and expiration:
                # Ignore exceptions that have passed their expiry date
                if datetime.utcnow() < expiration:
                    max_validity = max(max_validity, validity)
        return self.validity_interval(event) > max_validity

    def validity_interval(self, event):
        event_time = panther_nanotime_to_python_datetime(event.get("time"))
        expires = golang_nanotime_to_python_datetime(
            event.deep_get("identity", "expires", default=None)
        )
        if not event_time and expires:
            return False
        interval = expires - event_time
        return interval

    def title(self, event):
        identity = event.deep_get("identity", "user", default="<Cert with no User!?>")
        return f"A Certificate for [{identity}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}] has been issued for an unusually long time: {self.validity_interval(event)!r} "
