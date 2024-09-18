from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Optional

import pytz
from croniter import CroniterBadCronError, croniter
from panther_core.enriched_event import PantherEvent

from pypanther import Rule


class Period:
    def __init__(self, duration: timedelta):
        min_duration = timedelta(minutes=5)
        max_duration = timedelta(days=30)
        if not (min_duration <= duration <= max_duration):
            raise ValueError("Period must be set between 5 mins and 30 days")
        self.duration = duration

    @classmethod
    def from_minutes(cls, minutes: int):
        return cls(timedelta(minutes=int(minutes)))

    @classmethod
    def from_hours(cls, hours: int):
        return cls(timedelta(hours=int(hours)))

    @classmethod
    def from_days(cls, days: int):
        return cls(timedelta(days=int(days)))

    def total_minutes(self):
        return int(self.duration.total_seconds() // 60)

    def total_hours(self):
        return int(self.duration.total_seconds() // 3600)

    def total_days(self):
        return int(self.duration.total_seconds() // 86400)

    def to_string(self):
        total_seconds = self.duration.total_seconds()
        days = int(total_seconds // 86400)
        hours = int((total_seconds % 86400) // 3600)
        minutes = int((total_seconds % 3600) // 60)

        if days > 0:
            return f"{days}d"
        if hours > 0:
            return f"{hours}h"
        if minutes > 0:
            return f"{minutes}m"
        return f"{int(total_seconds)}s"

    def __str__(self):
        return self.to_string()


@dataclass
class Schedule:
    enabled: bool = True
    timeout_mins: int = 5
    cron: Optional[croniter] = None
    period: Optional[Period] = None

    def __init__(
        self,
        enabled: bool = True,
        timeout_mins: int = 5,
        cron: Optional[str] = None,
        period: Optional[Period] = None,
    ):
        self.enabled = enabled
        self.timeout_mins = timeout_mins
        self.period = period
        if cron:
            try:
                # Anchor croniter to midnight UTC
                midnight_utc = datetime.now(pytz.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                self.cron = croniter(cron, midnight_utc)
            except CroniterBadCronError:
                raise ValueError(f"Invalid cron expression: {cron}")
        else:
            self.cron = None

        if not self.cron and not self.period:
            raise ValueError("Either cron or period must be provided")
        if self.cron and self.period:
            raise ValueError("Cannot provide both cron and period")

    def __repr__(self):
        return f"Schedule(enabled={self.enabled}, timeout_mins={self.timeout_mins}, cron='{self.cron}', period='{self.period}')"

    def get_next_run_time(self, start_time=None):
        if not self.cron:
            raise ValueError("Cron expression is not set")
        return self.cron.get_next(datetime, start_time)

    def get_prev_run_time(self, start_time=None):
        if not self.cron:
            raise ValueError("Cron expression is not set")
        return self.cron.get_prev(datetime, start_time)


class Query(ABC):
    _analysis_type = "QUERY"
    description: str = ""
    query_type: Literal["PantherFlow", "SQL"]
    expression: str
    schedule: Schedule

    def __init__(self, expression: str, schedule: Schedule, description: str = ""):
        self.description = description
        self.expression = expression
        self.schedule = schedule

    @property
    def id(self):
        return self.__class__.__name__

    @abstractmethod
    def validate(self):
        """Ensure search syntax is proper."""


class PantherFlowQuery(Query):
    query_type: Literal["PantherFlow"] = "PantherFlow"

    def validate(self):
        pass


class SQLQuery(Query):
    query_type: Literal["SQL"] = "SQL"

    def validate(self):
        pass


class ScheduledRule(Rule, ABC):
    _analysis_type = "SCHEDULED_RULE"
    query: Query
    period: Period

    def rule(self, event: PantherEvent) -> bool:
        """Optional method to further filter the results of the query. Defaults to True to avoid redundant code."""
        return True

    def query(self) -> Query:
        """Return the query object to be executed."""
        return self.query
