import argparse
import os
from typing import Tuple

from pypanther.sdk.alerts import get_alert_stats


def run(args: argparse.Namespace) -> Tuple[int, str]:
    stats = get_alert_stats()
    return 0, stats
