from unittest import TestCase

import pytest

from pypanther import list_rules
from pypanther.main import setup_parser


@pytest.mark.parametrize(
    "cmd",
    [
        "list rules --managed",
        "list rules --managed --log-types a b",
        "list rules --managed --id abc",
        "list rules --managed --create-alert true",
        "list rules --managed --dedup-period-minutes 5",
        "list rules --managed --display-name 5",
        "list rules --managed --enabled true",
        "list rules --managed --summary-attributes a b",
        "list rules --managed --threshold 9",
        "list rules --managed --tags a b",
        "list rules --managed --default-severity low",
        "list rules --managed --default-description desc",
        "list rules --managed --default-reference ref",
        "list rules --managed --default-runbook run",
        "list rules --managed --default-destinations a b",
    ],
)
def test_list_managed_rules(cmd: str) -> None:
    args = setup_parser().parse_args(cmd.split(" "))
    code, err = list_rules.run(args)
    assert code == 0
    assert err == ""


class TestListRules(TestCase):
    def test_list_rules_log_types_filter(self):
        args = setup_parser().parse_args("list rules --managed --log-types a b".split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""

    def test_list_rules_id_filter(self):
        args = setup_parser().parse_args("list rules --managed --id abc".split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""

    def test_list_rules_create_alert_filter(self):
        args = setup_parser().parse_args("list rules --managed --create-alert true".split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""

    def test_list_rules_dedup_period_minutes_filter(self):
        args = setup_parser().parse_args("list rules --managed --dedup-period-minutes 5".split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""

    def test_list_rules_display_name_filter(self):
        args = setup_parser().parse_args("list rules --managed --display-name 5".split(" "))
        code, err = list_rules.run(args)
        assert code == 0
        assert err == ""
