import argparse
import datetime
import inspect
import json
import logging
import os

from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport

from pypanther import get_panther_rules

load_dotenv()
API_HOST = os.getenv("GRAPHQL_ENDPOINT")
API_TOKEN = os.getenv("API_KEY")

# Define the GraphQL query
find_alerts = gql(
    """
    query FindAlerts($input: AlertsInput!) {
      alerts(input: $input) {
        edges {
          node {
            id
            title
            type
            origin {
                ... on Detection {
                    id
                    name
                }
            }
            severity
            status
            createdAt
            firstEventOccurredAt
            lastReceivedEventAt
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """,
)

transport = AIOHTTPTransport(
    url=API_HOST,
    headers={"X-API-Key": API_TOKEN},
)

client = Client(transport=transport, fetch_schema_from_transport=True)


def _get_date_range(days_ago: int = 7) -> tuple:
    """
    Get the date range for the query
    Args:
        days_ago (int): The number of days to go back
    Returns:
        tuple: A tuple of the start and end date
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    # Calculate the start of the current month
    # from_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="milliseconds").replace("+00:00", "Z") # month to date
    from_date = (
        (now - relativedelta(days=days_ago)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )  # one month ago
    # Current date and time
    to_date = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return from_date, to_date


def list_alerts_by_rule_id(rule_id: str, days_ago: int = 7) -> list:
    """
    List all alerts (except INFO) via the API for a given rule id
    Args:
        rule_id (str): The rule id to fetch alerts for
    Returns:
        list: A list of alerts
    """
    from_date, to_date = _get_date_range(days_ago)
    alerts = []
    has_more = True
    cursor = None

    while has_more:
        query_data = client.execute(
            find_alerts,
            variable_values={
                "input": {
                    "detectionId": rule_id,
                    "createdAtAfter": from_date,
                    "createdAtBefore": to_date,
                    "subtypes": ["RULE"],
                    "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "cursor": cursor,
                },
            },
        )
        alerts.extend([edge["node"] for edge in query_data["alerts"]["edges"]])
        has_more = query_data["alerts"]["pageInfo"]["hasNextPage"]
        cursor = query_data["alerts"]["pageInfo"]["endCursor"]
    return alerts


def get_alert_stats(args: argparse.Namespace) -> list:
    """
    Fetches alert metrics via the API
    """
    fetch_metrics_query = gql("""
    query FetchMetrics($input: MetricsInput!) {
        metrics(input: $input) {
            alertsPerRule {
                entityId
                label
                value
            }
        }
    }
    """)

    last_days = args.days
    from_date, to_date = _get_date_range(last_days)
    metrics_input = {
        "fromDate": from_date,
        "toDate": to_date,
        "intervalInMinutes": None,  # Leave empty for automatic interval
    }
    # Execute the query with the calculated date range
    query_data = client.execute(fetch_metrics_query, variable_values={"input": metrics_input})
    alerts = query_data.get("metrics", {}).get("alertsPerRule", [])

    logging.info("Getting alert metrics for %d rules in the last %dd", len(alerts), last_days)
    alert_stats = []
    for alert in alerts:
        # Skip test rules
        if "test" in alert["entityId"].lower():
            logging.info("Skipping test rule %s", alert["entityId"])
            continue
        alert_count = alert["value"]
        if alert_count > 0:
            # Find the matching pypanther rule and continue if not found
            rule = get_panther_rules(id=alert["entityId"] + "-prototype")
            if not rule:
                continue
            # Get the alert details for the rule
            logging.debug("Getting alerts for %s...", alert["entityId"])
            alerts = list_alerts_by_rule_id(alert["entityId"])
            #
            output = {}
            if any(alert["severity"] != "INFO" for alert in alerts):
                output["rule_id"] = alert["entityId"]
                output["alert_count"] = alert_count
                output["alerts"] = []
                for alert in alerts:
                    del alert["origin"]
                    del alert["type"]
                    alert["alert_id"] = alert.pop("id")
                    output["alerts"].append(alert)
                if rule:
                    output["rule_source_code"] = inspect.getsource(rule[0])
                alert_stats.append(output)
    return 0, json.dumps(alert_stats)
