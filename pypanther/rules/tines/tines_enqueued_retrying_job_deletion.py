from pypanther import LogType, Rule, RuleTest, Severity, panther_managed
from pypanther.helpers.tines import tines_alert_context


@panther_managed
class TinesEnqueuedRetryingJobDestruction(Rule):
    id = "Tines.Enqueued.Retrying.Job.Destruction-prototype"
    display_name = "Tines Enqueued/Retrying Job Deletion"
    log_types = [LogType.TINES_AUDIT]
    tags = ["Tines"]
    default_severity = Severity.LOW
    default_description = "Currently enqueued or retrying jobs were cleared"
    default_runbook = (
        "Possible data destruction. Please reach out to the user and confirm this was done for valid business reasons."
    )
    default_reference = "https://www.tines.com/docs/self-hosting/job-management"

    def rule(self, event):
        return event.get("operation_name", "<NO_OPERATION_NAME>") in ["JobsQueuedDeletion", "JobsRetryingDeletion"]

    def title(self, event):
        operation = event.get("operation_name", "<NO_OPERATION_NAME>")
        user = event.get("user_email", "<NO_USER_EMAIL>")
        tines_instance = event.get("p_source_label", "<NO_SOURCE_LABEL>")
        return f"Tines [{operation}] performed by [{user}] on [{tines_instance}]."

    def alert_context(self, event):
        return tines_alert_context(event)

    tests = [
        RuleTest(
            name="Trigger - JobsQueuedDeletion",
            expected_result=True,
            log={
                "created_at": "2023-06-13 15:14:46",
                "id": 1234,
                "operation_name": "JobsQueuedDeletion",
                "p_source_label": "tines-log-source-name",
                "request_ip": "98.224.225.84",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (  KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "tenant_id": "1337",
                "user_email": "user@email.com",
                "user_id": "7331",
                "user_name": "Tines User Person",
            },
        ),
        RuleTest(
            name="Trigger - JobsRetryingDeletion",
            expected_result=True,
            log={
                "created_at": "2023-06-13 15:14:46",
                "id": 1234,
                "operation_name": "JobsRetryingDeletion",
                "p_source_label": "tines-log-source-name",
                "request_ip": "98.224.225.84",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (  KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "tenant_id": "1337",
                "user_email": "user@email.com",
                "user_id": "7331",
                "user_name": "Tines User Person",
            },
        ),
        RuleTest(
            name="Tines Login",
            expected_result=False,
            log={
                "created_at": "2023-05-17 14:45:19",
                "id": 7888888,
                "operation_name": "Login",
                "p_source_label": "tines-log-source-name",
                "request_ip": "12.12.12.12",
                "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
                "tenant_id": "8888",
                "user_email": "user@company.com",
                "user_id": "17171",
                "user_name": "user at company dot com",
            },
        ),
    ]
