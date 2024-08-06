from datetime import datetime, timedelta
from typing import Dict, Tuple

from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.panther_base_helpers import (
    golang_nanotime_to_python_datetime,
    panther_nanotime_to_python_datetime,
)

teleport_long_lived_certs_tests: list[RuleTest] = [
    RuleTest(
        name="A certificate was created for the default period of 1 hour",
        expected_result=False,
        log={
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
                "logins": ["-teleport-nologin-88888888-4444-4444-4444-222222222222", "-teleport-internal-join"],
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
    RuleTest(
        name="A certificate was created for longer than the default period of 1 hour",
        expected_result=True,
        log={
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
                "logins": ["-teleport-nologin-88888888-4444-4444-4444-222222222222", "-teleport-internal-join"],
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


@panther_managed
class TeleportLongLivedCerts(Rule):
    id = "Teleport.LongLivedCerts-prototype"
    display_name = "A long-lived cert was created"
    log_types = [LogType.GRAVITATIONAL_TELEPORT_AUDIT]
    tags = ["Teleport"]
    default_severity = Severity.MEDIUM
    default_description = "An unusually long-lived Teleport certificate was created"
    reports = {"MITRE ATT&CK": ["TA0003:T1098"]}
    default_reference = "https://goteleport.com/docs/management/admin/"
    default_runbook = "Teleport certificates are usually issued for a short period of time. Alert if long-lived certificates were created.\n"
    summary_attributes = ["event", "code", "time", "identity"]
    tests = teleport_long_lived_certs_tests
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
        if event.get("event") != "cert.create":
            return False
        max_validity = self.MAXIMUM_NORMAL_VALIDITY_INTERVAL + self.ISSUANCE_GRACE_PERIOD
        for role in event.deep_get("identity", "roles", default=[]):
            validity, expiration = self.CLUSTER_ROLE_MAX_VALIDITIES.get(event.get("cluster_name"), {}).get(
                role,
                (None, None),
            )
            if validity and expiration:
                # Ignore exceptions that have passed their expiry date
                if datetime.utcnow() < expiration:
                    max_validity = max(max_validity, validity)
        return self.validity_interval(event) > max_validity

    def validity_interval(self, event):
        event_time = panther_nanotime_to_python_datetime(event.get("time"))
        expires = golang_nanotime_to_python_datetime(event.deep_get("identity", "expires", default=None))
        if not event_time and expires:
            return False
        interval = expires - event_time
        return interval

    def title(self, event):
        identity = event.deep_get("identity", "user", default="<Cert with no User!?>")
        return f"A Certificate for [{identity}] on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}] has been issued for an unusually long time: {self.validity_interval(event)!r} "
