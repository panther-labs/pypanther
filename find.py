import inspect
from collections import Counter, defaultdict
from importlib import import_module
from pkgutil import walk_packages
from typing import List

from pypanther.base import PANTHER_RULE_ALL_ATTRS, PANTHER_RULE_ALL_METHODS, PantherRule
from pypanther.get import get_panther_rules


def get_rules_by_category():
    rules = defaultdict(list)
    p_a_r = import_module("pypanther.rules")
    for module_info in walk_packages(p_a_r.__path__, "pypanther.rules."):
        if len(module_info.name.split(".")) > 3:
            m = import_module(module_info.name)
            group = module_info.name.split(".")[2]
            for item in dir(m):
                attr = getattr(m, item)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, PantherRule)
                    and attr is not PantherRule
                ):
                    rules[group].append(attr)
    return rules


def compare_rules(rules: list[type[PantherRule]]):
    consistent_attrs = []
    for attr in PANTHER_RULE_ALL_ATTRS:
        all_attrs = [getattr(cls, attr) for cls in rules]
        unique_attrs: List = []
        for x in all_attrs:
            if unique_attrs.count(x) == 0:
                unique_attrs.append(x)

        if len(unique_attrs) == 1:
            if hasattr(PantherRule, attr) and unique_attrs[0] == getattr(PantherRule, attr):
                continue
            consistent_attrs.append(attr)

    consistent_methods = []
    for method in PANTHER_RULE_ALL_METHODS:
        all_methods = [inspect.getsource(getattr(cls, method)) for cls in rules]
        unique_methods: List = []
        for x in all_methods:
            if unique_methods.count(x) == 0:
                unique_methods.append(x)
        if len(unique_methods) == 1 and unique_methods is not None:
            if hasattr(PantherRule, method) and unique_methods[0] == inspect.getsource(
                getattr(PantherRule, method)
            ):
                continue
            consistent_methods.append(method)

    return consistent_attrs, consistent_methods


def stats_for_category():
    rules = get_rules_by_category()
    attr_count = Counter()
    method_count = Counter()
    for attr in PANTHER_RULE_ALL_ATTRS:
        attr_count[attr] = 0
    for method in PANTHER_RULE_ALL_METHODS:
        method_count[method] = 0

    for group, rule_list in rules.items():
        if len(rule_list) == 1:
            continue
        consistent_attrs, consistent_methods = compare_rules(rule_list)
        print(f"[{group}]: {len(rule_list)}")
        print(f"\tattrs: {consistent_attrs}")
        print(f"\tmethods: {consistent_methods}")

        for attr in consistent_attrs:
            attr_count[attr] += 1
        for method in consistent_methods:
            method_count[method] += 1

    print("Attributes:")
    for k, v in attr_count.items():
        print(f"\t{k}: {v}")

    print("Methods:")
    for k, v in method_count.items():
        print(f"\t{k}: {v}")


def stats_for_logtype():
    rules_by_logtypes = defaultdict(list)
    for rule in get_panther_rules():
        if len(rule.LogTypes) == 0:
            rules_by_logtypes["None"].append(rule)
            continue
        if len(rule.LogTypes) > 1:
            rules_by_logtypes["Multiple"].append(rule)
            continue
        rules_by_logtypes[rule.LogTypes[0]].append(rule)

    for group, rule_list in rules_by_logtypes.items():
        if len(rule_list) == 1:
            continue
        consistent_attrs, consistent_methods = compare_rules(rule_list)
        print(f"[{group}]: {len(rule_list)}")
        print(f"\tattrs: {consistent_attrs}")
        print(f"\tmethods: {consistent_methods}")


if __name__ == "__main__":
    # stats_for_category()
    stats_for_logtype()
