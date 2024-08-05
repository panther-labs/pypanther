import datetime
import inspect
import json
import os

from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport

from pypanther import get_panther_rules

load_dotenv()
GRAPHQL_ENDPOINT = os.getenv("GRAPHQL_ENDPOINT")
API_KEY = os.getenv("API_KEY")

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
    url=GRAPHQL_ENDPOINT,
    headers={"X-API-Key": API_KEY},
)

client = Client(transport=transport, fetch_schema_from_transport=True)


def list_alerts_by_id(rule_id: str) -> list:
    # days_ago = (
    #     (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=created_at_after_days))
    #     .isoformat(timespec="milliseconds")
    #     .replace("+00:00", "Z")
    # )
    # current_date = (
    #     datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    # )

    # Get the current date and time
    now = datetime.datetime.now(datetime.timezone.utc)
    # Calculate the start of the current month
    # from_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="milliseconds").replace("+00:00", "Z") # month to date
    from_date = (now - relativedelta(days=7)).isoformat(timespec="milliseconds").replace("+00:00", "Z")  # one month ago

    # Current date and time
    to_date = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    # an accumulator that holds all alerts that we fetch all pages
    alerts = []
    # a helper to know when to exit the loop
    has_more = True
    # the pagination cursor
    cursor = None

    # Keep fetching pages until there are no more left
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


def get_alert_stats():
    # Define the GraphQL query to fetch metrics
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

    # Get the current date and time
    now = datetime.datetime.now(datetime.timezone.utc)
    # Month to date
    # from_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    # Last month
    from_date = (now - relativedelta(days=7)).isoformat(timespec="milliseconds").replace("+00:00", "Z")  # one month ago
    # Current date and time
    to_date = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    # Prepare the input for the query
    metrics_input = {
        "fromDate": from_date,
        "toDate": to_date,
        "intervalInMinutes": None,  # Leave empty for automatic interval
    }

    # Execute the query with the calculated date range
    query_data = client.execute(fetch_metrics_query, variable_values={"input": metrics_input})
    return query_data.get("metrics", {}).get("alertsPerRule", [])


alerts = get_alert_stats()
print(f"Getting details for {len(alerts)} rules...")
for alert in alerts:
    if "test" in alert["entityId"].lower():
        print("Skipping test rule %s..." % alert["entityId"])
        continue
    alert_count = alert["value"]
    if alert_count > 0:
        print(f"Getting alerts for {alert['entityId']}...")
        alerts = list_alerts_by_id(alert["entityId"])

        rule = get_panther_rules(id=alert["entityId"] + "-prototype")
        if not rule:
            continue

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
                output["rule_source_code"] = json.dumps(inspect.getsource(rule[0]))
            print(output)
