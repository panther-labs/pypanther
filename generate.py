import argparse
import ast
import difflib
import functools
import inspect
import os
import re
import shutil
import subprocess
import sys
from multiprocessing import Pool
from pathlib import Path
from typing import List, Optional, Set

from ast_comments import Comment, parse, unparse
from ruamel.yaml import YAML

import pypanther
from pypanther import DataModel, DataModelMapping, LogType, Rule, RuleMock, RuleTest, Severity, panther_managed

ID_POSTFIX = "-prototype"


def perror(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def to_snake_case(name: str) -> str:
    res = [name[0].lower()]
    for c in name[1:]:
        if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            res.append("_")
            res.append(c.lower())
        else:
            res.append(c)

    return "".join(res)


def convert_rule_attribute_name(name: str) -> str:
    match name:
        case "RuleID":
            return "id"
        case "Severity":
            return "default_severity"
        case "OutputIds":
            return "default_destinations"
        case "Runbook":
            return "default_runbook"
        case "Reference":
            return "default_reference"
        case "Description":
            return "default_description"
        case _:
            return to_snake_case(name)


def convert_rule(filepath: Path, helpers: Set[str]) -> Optional[str]:
    imports = [
        f"from pypanther import {Rule.__name__}, {RuleTest.__name__}, {Severity.__name__}, {LogType.__name__}, {RuleMock.__name__}, {panther_managed.__name__}",
    ]

    p = Path(filepath)

    with open(p, "rb") as f:
        yaml = YAML(typ="safe")
        loaded = yaml.load(f)

    analysis_type = loaded["AnalysisType"]
    if analysis_type not in ("rule", "scheduled_rule"):
        raise NotImplementedError(f"AnalysisType must be 'rule', not {analysis_type}")

    class_name = to_ascii(loaded["RuleID"])

    assignments: List[ast.AST] = []
    for k, v in loaded.items():
        if k in {"AnalysisType", "Filename", "Tests"}:
            continue
        if hasattr(Rule, to_snake_case(k)) and v == getattr(Rule, to_snake_case(k)):
            continue
        if k == "Detection":
            raise NotImplementedError("Detection not implemented")

        if k == "Reports":
            for k2, v2 in v.items():
                v[k2] = [str(x) if isinstance(x, (int, float)) else x for x in v2]

        if k == "Tags" and "deprecated" in {x.lower() for x in v}:
            return None

        if k == "Description" and "deprecated" in v.lower():
            return None

        if k == "DisplayName" and "deprecated" in v.lower():
            return None

        value: ast.AST = ast.Constant(value=v)
        if k == "Severity":
            value = ast.Name(id=f"{Severity.__name__}.{v.upper()}", ctx=ast.Load())
        if k == "LogTypes":
            log_type_elts = []
            for x in v:
                log_type_elts.append(
                    ast.Attribute(
                        value=ast.Name(id=f"{LogType.__name__}", ctx=ast.Load()),
                        attr=LogType.get_attribute_name(x),
                        ctx=ast.Load(),
                    ),
                )
            value = ast.List(elts=log_type_elts)
        if k == "RuleID":
            value = ast.Constant(value=v + ID_POSTFIX)

        assignments.append(
            ast.Assign(
                targets=[ast.Name(id=convert_rule_attribute_name(k), ctx=ast.Store())],
                value=value,
                lineno=0,
            ),
        )

    tests = loaded.get("Tests", [])
    elts = []
    for test in tests:
        keywords = [
            ast.keyword(arg="name", value=ast.Constant(value=test["Name"])),
            ast.keyword(arg="expected_result", value=ast.Constant(value=test["ExpectedResult"])),
            ast.keyword(arg="log", value=ast.Constant(value=test["Log"])),
        ]

        if "Mocks" in test:
            if any(mock["objectName"] == "filter_include_event" for mock in test["Mocks"]):
                # tests that test the filter_include_event are not applicable because
                # we removed the filter_include_event function
                continue

            mocks = []
            for mock in test["Mocks"]:
                if mock["objectName"] == "filter_include_event":
                    # skip filter_include_event mocks
                    continue

                mock_keywords = []
                for k, v in mock.items():
                    mock_keywords.append(ast.keyword(arg=to_snake_case(k), value=ast.Constant(value=v)))

                mocks.append(
                    ast.Call(
                        func=ast.Name(id=RuleMock.__name__, ctx=ast.Load()),
                        args=[],
                        keywords=mock_keywords,
                    ),
                )

            keywords.insert(
                2,
                ast.keyword(arg="mocks", value=ast.List(elts=mocks)),
            )

        elts.append(
            ast.Call(
                func=ast.Name(id=RuleTest.__name__, ctx=ast.Load()),
                args=[],
                keywords=keywords,
            ),
        )

    tree = parse_py(
        p.with_suffix(".py"),
        class_name,
        parse("\n".join(imports)).body,
        assignments,
        elts,
        helpers,
    )

    if p.name == "cloudflare_httpreq_bot_high_volume.yml":
        # custom modifications for this rule
        DropStr(
            [
                "from unittest.mock import MagicMock",
                """if isinstance(filter_include_event, MagicMock):
    pass""",
            ],
        ).visit(tree)

    return unparse(tree)


def run_ruff(paths: List[Path]):
    subprocess.run(["ruff", "check", "--fix", "--ignore", "E402"] + list(paths), check=True)
    subprocess.run(["ruff", "format"] + list(paths), check=True)


def to_ascii(s):
    ret = "".join([i if ord("A") <= ord(i) <= ord("z") or ord("0") <= ord(i) < ord("9") else "" for i in s])

    while ret[0].isdigit():
        ret = ret[1:]
    return ret


RULE_FUNCTIONS = {
    "rule",
    "severity",
    "title",
    "dedup",
    "destinations",
    "runbook",
    "reference",
    "description",
    "alert_context",
}

CAMEL_TO_SNAKE_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def camel_to_snake(name: str) -> str:
    return CAMEL_TO_SNAKE_RE.sub("_", name).lower()


def parse_py(
    filepath: Path,
    class_name: str,
    imports: List[ast.Import],
    assignments: List[ast.AST],
    tests: List[ast.Call],
    helpers: Set[str],
) -> ast.Module:
    with open(filepath, encoding="utf-8") as f:
        lines = f.read()
    tree = parse(lines)

    def is_func(x):
        return isinstance(x, ast.FunctionDef)  # and x.name in RULE_FUNCTIONS

    def is_import(x):
        return isinstance(x, (ast.Import, ast.ImportFrom))

    # strip rule functions
    els, functions = (
        [x for x in tree.body if not is_func(x)],
        [x for x in tree.body if is_func(x)],
    )

    # strip global variables
    imps, other = [x for x in els if is_import(x)], [x for x in els if not is_import(x)]

    # rewrite imports
    rewrite_imports_ast(imps, helpers)

    for funcs in functions:
        # add self as first argument
        funcs.args.args.insert(0, ast.arg(arg="self", annotation=None))

    function_names = {f.name for f in functions}
    variable_names = set()
    for a in other:
        if isinstance(a, ast.Assign):
            variable_names |= {t.id for t in a.targets if isinstance(t, ast.Name)}
        elif isinstance(a, ast.AnnAssign):
            if isinstance(a.target, ast.Name):
                variable_names.add(a.target.id)

    delete_comments = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            for x in node.names:
                variable_names.add(x)
        if isinstance(node, Comment):
            if node.value in (
                "# pylint: disable=global-statement",
                "# pylint: disable=global-variable-undefined",
            ):
                delete_comments.add(node)

    for a in other:
        if isinstance(a, (ast.Assign, ast.AnnAssign)):
            if a.value is None:
                continue
            for node in ast.walk(a.value):
                if isinstance(node, ast.Name) and node.id in variable_names:
                    node.id = "self." + node.id
        else:
            for node in ast.walk(a):
                if isinstance(node, ast.Name) and node.id in variable_names:
                    node.id = "self." + node.id

    for func in functions:
        for node in ast.walk(func):
            if isinstance(node, ast.Name) and node.id in variable_names:
                node.id = "self." + node.id

    tree.body = imports + imps

    test_attribute = []

    if len(tests):
        test_attribute.append(
            ast.Assign(
                targets=[ast.Name(id="tests", ctx=ast.Store())],
                value=ast.List(elts=tests),
                simple=1,
                lineno=0,
            ),
        )

    # add class def to tree
    c = ast.ClassDef(
        name=class_name,
        bases=[ast.Name(Rule.__name__, ctx=ast.Load())],
        keywords=[],
        decorator_list=[],
        body=assignments + other + functions + test_attribute,
    )
    c.decorator_list.append(ast.Name(id="panther_managed", ctx=ast.Load()))
    tree.body.append(c)

    # rewrite function calls and globals since they are now part of the class
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in function_names:
            node.id = "self." + node.id

    DropGlobal().visit(tree)
    Drop(delete_comments).visit(tree)

    # rewrite filters
    DropFilterIncludeEvent().visit(tree)

    # constant propogation
    ConstantPropogation().visit(tree)

    return tree


def rewrite_imports_ast(imps: List[ast.AST], helpers: Set[str]):
    # rewrite imports
    for imp in imps:
        if isinstance(imp, ast.Import):
            for i, name in enumerate(imp.names):
                if name.name.split(".")[0] in helpers:
                    asname = name.asname
                    if asname is None:
                        asname = name.name
                    imp.names[i] = ast.alias(
                        name="pypanther.helpers." + name.name.replace("_helpers", "").replace("panther_", ""),
                        asname=asname,
                    )
        elif isinstance(imp, ast.ImportFrom):
            if imp.module is not None and imp.module.split(".")[0] in helpers:
                imp.module = "pypanther.helpers." + imp.module.replace("_helpers", "").replace("panther_", "")


def rewrite_imports_str(code: str, helpers: Set[str]):
    # rewrite imports
    ret = []
    for line in code.splitlines():
        m = re.match(r"^ *import (\S*)( *as *(.*))?", line)
        if m is not None:
            for name in m.group(1).split(","):
                if name.split(".")[0] in helpers:
                    line = line.replace(
                        name,
                        f"pypanther.helpers.{name}".replace("_helpers", "").replace("panther_", ""),
                    )

                    if m.group(2) is None and len(name.split(".")) == 1:
                        line += f" as {name}"

        m = re.match(r"^ *from (.*) import (.*)", line)
        if m is not None:
            if m.group(1).split(".")[0] in helpers:
                line = (
                    line.replace(m.group(1), "pypanther.helpers." + m.group(1))
                    .replace("_helpers", "")
                    .replace("panther_", "")
                )
        ret.append(line)

    return "\n".join(ret) + "\n"


class ConstantPropogation(ast.NodeTransformer):
    def visit_UnaryOp(self, node: ast.UnaryOp) -> Optional[ast.AST]:
        if isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Constant) and node.operand.value is True:
            return ast.Constant(value=False)
        return super().generic_visit(node)

    def visit_If(self, node: ast.If) -> Optional[ast.AST]:
        # visit children first
        visited_node = self.generic_visit(node)

        if isinstance(visited_node, ast.If) and isinstance(visited_node.test, ast.Constant):
            if visited_node.test.value is False and len(visited_node.orelse) == 0:
                return None

        return visited_node


class DropFilterIncludeEvent(ast.NodeTransformer):
    def visit_Call(self, node: ast.Call) -> Optional[ast.AST]:
        if isinstance(node.func, ast.Name) and node.func.id == "filter_include_event":
            return ast.Constant(value=True)
        return super().generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Optional[ast.AST]:
        node.names = [name for name in node.names if not name.name.startswith("pypanther.helpers.global_filter_")]
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Optional[ast.AST]:
        if node.module is not None and node.module.startswith("pypanther.helpers.global_filter_"):
            return None

        return node


class DropStr(ast.NodeTransformer):
    def __init__(self, drop: List[str]) -> None:
        super().__init__()
        self.should_drop = drop

    def visit(self, node: ast.AST) -> Optional[ast.AST]:
        if unparse(node) in self.should_drop:
            return None

        return super().generic_visit(node)


class Drop(ast.NodeTransformer):
    def __init__(self, drop: Set[ast.AST]) -> None:
        super().__init__()
        self.should_drop = drop

    def visit(self, node: ast.AST) -> Optional[ast.AST]:
        if node in self.should_drop:
            return None

        return super().generic_visit(node)


class DropGlobal(ast.NodeTransformer):
    def visit_Global(self, _: ast.Global) -> Optional[ast.AST]:
        return None


def convert_global_helpers(panther_analysis: Path) -> Set[str]:
    # walk the rules folder
    global_helpers_path = panther_analysis / "global_helpers"

    helpers_path = Path("pypanther") / "helpers"
    if helpers_path.exists():
        shutil.rmtree(helpers_path)
    helpers_path.mkdir(parents=True, exist_ok=True)
    Path(helpers_path / "__init__.py").touch()

    helpers = set()

    # get a list of all global helpers
    for p in (global_helpers_path).rglob("*.y*ml"):
        gh = YAML(typ="safe").load(p)

        if gh["AnalysisType"] != "global":
            perror(f"AnalysisType must be 'global', not {gh['AnalysisType']}")
            continue

        helpers.add(Path(gh["Filename"]).stem)

    paths = []
    for p in (global_helpers_path).rglob("*.y*ml"):
        gh = YAML(typ="safe").load(p)

        if gh["AnalysisType"] != "global":
            perror(f"AnalysisType must be 'global', not {gh['AnalysisType']}")
            continue

        description = gh.get("Description", "")

        with open(global_helpers_path / gh["Filename"], encoding="utf-8") as f:
            code = f.read()

        # strip panther_analysis from path
        if description:
            if description.endswith("\n") and not description.startswith("\n"):
                description = "\n" + description
            code = f'"""{description}"""\n' + code

        code = rewrite_imports_str(code, helpers)

        with open(
            helpers_path / gh["Filename"].replace("_helpers", "").replace("panther_", ""),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(code)

        helpers.add(Path(gh["Filename"]).stem)
        paths.append(helpers_path / gh["Filename"])

    return helpers


def convert_data_models(panther_analysis: Path, helpers: Set[str]):
    data_models_path = panther_analysis / "data_models"
    if Path("pypanther/data_models").exists():
        shutil.rmtree(Path("pypanther/data_models"))

    imports = f"from pypanther.base import {DataModel.__name__}, {DataModelMapping.__name__}, {LogType.__name__}"

    paths = []
    for p in (data_models_path).rglob("*.y*ml"):
        with open(p, "rb") as f:
            dm = YAML(typ="safe").load(f)

        if dm["AnalysisType"] != "datamodel":
            perror(f"AnalysisType must be 'datamodel', not {dm['AnalysisType']}")
            continue

        mappings = []
        for item in dm["Mappings"]:
            keywords = []
            for k, v in item.items():
                value: ast.AST = ast.Constant(value=v)
                if k == "Method":
                    value = ast.Name(id=v, ctx=ast.Load())
                keywords.append(ast.keyword(arg=to_snake_case(k), value=value))
            mappings.append(
                ast.Call(
                    func=ast.Name(id="DataModelMapping", ctx=ast.Load()),
                    args=[],
                    keywords=keywords,
                ),
            )

        classname = to_ascii(dm["DataModelID"])
        as_class = ast.ClassDef(
            name=classname,
            bases=[ast.Name(id=DataModel.__name__, ctx=ast.Load())],
            keywords=[],
            decorator_list=[],
            body=[
                ast.AnnAssign(
                    target=ast.Name(id="id", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=ast.Constant(value=dm["DataModelID"]),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="display_name", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=ast.Constant(value=dm.get("DisplayName", None)),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="enabled", ctx=ast.Store()),
                    annotation=ast.Name(id="bool", ctx=ast.Load()),
                    value=ast.Constant(value=dm["Enabled"]),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="log_types", ctx=ast.Store()),
                    annotation=ast.Subscript(
                        value=ast.Name(id="list", ctx=ast.Load()),
                        slice=ast.Index(value=ast.Name(id="str", ctx=ast.Load())),
                    ),
                    value=ast.List(
                        elts=[
                            ast.Name(
                                id=f"{LogType.__name__}.{LogType.get_attribute_name(x)}",
                                ctx=ast.Load(),
                            )
                            for x in dm["LogTypes"]
                        ],
                    ),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="mappings", ctx=ast.Store()),
                    annotation=ast.Subscript(
                        value=ast.Name(id="list", ctx=ast.Load()),
                        slice=ast.Index(value=ast.Name(id="DataModelMapping", ctx=ast.Load())),
                    ),
                    value=ast.List(elts=mappings, ctx=ast.Load()),
                    simple=1,
                ),
            ],
        )

        code = imports + "\n"
        if "Filename" in dm:
            with open(data_models_path / dm["Filename"], encoding="utf-8") as f:
                code += f.read()

        code = rewrite_imports_str(code, helpers)

        code += "\n\n" + unparse(as_class) + "\n"

        p_str = str(p.relative_to(panther_analysis)).replace("_data_model", "")
        p = Path("pypanther") / Path(p_str)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p.with_suffix(".py"), "w", encoding="utf-8") as f:
            f.write(code)

        paths.append(p.with_suffix(".py"))

    add_inits(Path("pypanther/data_models"))


def add_inits(path: Path):
    for dirpath, dirnames, filenames in os.walk(path):
        if "__init__.py" not in filenames:
            (Path(dirpath) / "__init__.py").touch()
        if "__pycache__" in dirnames:
            dirnames.remove("__pycache__")


def get_classes_from_file(py_file: Path):
    """Parses a Python file and returns a list of class, function, and variable names defined in it."""
    with open(py_file) as file:
        node = ast.parse(file.read(), filename=py_file)

    classes = [n.name for n in node.body if isinstance(n, ast.ClassDef)]

    return classes


def create_init_py(directory: Path, root_directory: Path):
    init_file = directory / "__init__.py"
    relative_dir = directory.relative_to(root_directory)
    module_path = ".".join(relative_dir.parts)

    with open(init_file, "w") as f:
        for py_file in directory.glob("*.py"):
            if py_file.name == "__init__.py":
                continue  # Skip the __init__.py file itself

            module_name = py_file.stem
            classes = get_classes_from_file(py_file)
            for cls in classes:
                f.write(f"from pypanther.rules.{module_path}.{module_name} import {cls} as {cls}\n")

    print(f"Created __init__.py in {directory}")


def process_directory(root_directory: Path):
    for dirpath, _dirnames, filenames in os.walk(root_directory):
        if any(f.endswith(".py") for f in filenames):
            create_init_py(Path(dirpath), root_directory)


def _convert_rules(p: Path, panther_analysis: Path, helpers: Set[str]):
    try:
        new_rule = convert_rule(p, helpers)
    except NotImplementedError as e:
        perror(f"Error processing {p}: {e}")
        return

    if new_rule is None:
        return

    # strip panther_analysis from path
    p_str = str(p.relative_to(panther_analysis)).replace("_rules", "")
    p = Path("pypanther") / Path(p_str)

    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p.with_suffix(".py"), "w", encoding="utf-8") as f:
        f.write(new_rule)


def convert_rules(panther_analysis: Path, helpers: Set[str]):
    rules_path = panther_analysis / "rules"
    if Path("pypanther/rules").exists():
        shutil.rmtree(Path("pypanther/rules"))

    _convert_rules_curry = functools.partial(_convert_rules, panther_analysis=panther_analysis, helpers=helpers)
    with Pool() as pool:
        pool.map(_convert_rules_curry, rules_path.rglob("*.y*ml"))

    # __init__.py to all folders
    add_inits(Path("pypanther") / "rules")
    process_directory(Path("pypanther") / "rules")


def convert_queries(
    panther_analysis: Path,
):
    queries_path = panther_analysis / "queries"
    paths = []
    for p in queries_path.rglob("*.y*ml"):
        with open(p, "rb") as f:
            query = YAML(typ="safe").load(f)

        if query["AnalysisType"] not in ("scheduled_query", "saved_query"):
            perror(
                "AnalysisType must be 'scheduled_query' or 'saved_query'",
                f" not {query['AnalysisType']}",
            )
            continue

        classname = to_ascii(query["QueryName"])

        imports = """from typing import List
from pypanther.base import PantherDataModel, PantherQuerySchedule

"""

        schedule: ast.AST = ast.Constant(value=None)
        if "Schedule" in query:
            schedule = ast.Call(
                func=ast.Name(id="PantherQuerySchedule", ctx=ast.Load()),
                args=[],
                keywords=[
                    ast.keyword(
                        arg="CronExpression",
                        value=ast.Constant(value=query["Schedule"].get("CronExpression", "")),
                    ),
                    ast.keyword(
                        arg="RateMinutes",
                        value=ast.Constant(value=query["Schedule"].get("RateMinutes", "")),
                    ),
                    ast.keyword(
                        arg="TimeoutMinutes",
                        value=ast.Constant(value=query["Schedule"]["TimeoutMinutes"]),
                    ),
                ],
            )

        query_class = ast.ClassDef(
            name=classname,
            bases=[ast.Name(id=DataModel.__name__, ctx=ast.Load())],
            keywords=[],
            decorator_list=[],
            body=[
                ast.AnnAssign(
                    target=ast.Name(id="QueryName", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=ast.Constant(value=query["QueryName"]),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="Enabled", ctx=ast.Store()),
                    annotation=ast.Name(id="bool", ctx=ast.Load()),
                    value=ast.Constant(value=query.get("Enabled", None)),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="Tags", ctx=ast.Store()),
                    annotation=ast.Subscript(
                        value=ast.Name(id="List", ctx=ast.Load()),
                        slice=ast.Index(value=ast.Name(id="str", ctx=ast.Load())),
                    ),
                    value=ast.List(elts=[ast.Constant(value=x) for x in query.get("Tags", [])]),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="Description", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=ast.Constant(value=query.get("Description", "")),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="Query", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=to_lines(query.get("Query", "")),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="Schedule", ctx=ast.Store()),
                    annotation=ast.Name(id="PantherQuerySchedule", ctx=ast.Load()),
                    value=schedule,
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="SnowflakeQuery", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=to_lines(query.get("SnowflakeQuery", "")),
                    simple=1,
                ),
                ast.AnnAssign(
                    target=ast.Name(id="AthenaQuery", ctx=ast.Store()),
                    annotation=ast.Name(id="str", ctx=ast.Load()),
                    value=to_lines(query.get("AthenaQuery", "")),
                    simple=1,
                ),
            ],
        )

        new_rule = imports + unparse(query_class)

        # strip panther_analysis from path
        p = Path("pypanther") / p.relative_to(panther_analysis)

        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p.with_suffix(".py"), "w", encoding="utf-8") as f:
            f.write(new_rule)

        paths.append(p.with_suffix(".py"))

    add_inits(Path("pypanther") / "queries")


def to_lines(s: str) -> ast.AST:
    elems = []
    for line in s.splitlines():
        elems.append(ast.Constant(value=line))

    return ast.Call(
        func=ast.Attribute(value=ast.Constant(value="\n"), attr="join", ctx=ast.Load()),
        args=[ast.List(elts=elems)],
        keywords=[],
    )


def strip_global_filters():
    for p in Path("pypanther/helpers").rglob("global_filter_*.py"):
        p.unlink()


def delete_unmodified_panther_managed_rules() -> None:
    # assuming that "pypanther" is available as a module and it
    # contains the V2-converted panther managed rules
    original_rules_path = Path(inspect.getfile(pypanther)).parent / "rules"

    # assuming this directory has been created by the conversion
    # functions called before this one
    generated_rules_path = Path("pypanther/rules/")

    to_delete = []
    for generated_path in generated_rules_path.glob("**/[A-Za-z]*.py"):
        # assuming that the directory structure of the generated rules is
        # identical to the structure of the pypanther module rules directory
        original_path = original_rules_path / (generated_path.relative_to(generated_rules_path))

        with original_path.open(mode="rb") as fo, generated_path.open(mode="rb") as fg:
            original_code = ast.parse(fo.read())
            code = ast.parse(fg.read())

        # assuming that ruff has formatted the generated file before this comparison
        diff = list(
            difflib.unified_diff(ast.unparse(original_code).splitlines(), ast.unparse(code).splitlines(), lineterm=""),
        )
        if not diff:
            to_delete.append(generated_path)

    # delete unmodified rules as identified above
    for path in to_delete:
        path.unlink()
        if not any(path.parent.iterdir()):
            path.parent.rmdir()

    # delete empty directories or directories that contain only __init__.py files
    for root, dirs, files in os.walk(str(generated_rules_path), topdown=False):
        if len(files) == 1 and files[0] == "__init__.py":
            Path(os.path.join(root, files[0])).unlink()
        for name in dirs:
            directory = Path(os.path.join(root, name))
            if not any(directory.iterdir()):
                # directory is empty
                directory.rmdir()


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("panther_analysis_path", type=Path)
    parser.add_argument("--keep-all-rules", default=False, action="store_true")
    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    panther_analysis = args.panther_analysis_path
    keep_only_modified_rules = not args.keep_all_rules

    helpers = convert_global_helpers(panther_analysis)
    convert_data_models(panther_analysis, helpers)
    convert_rules(panther_analysis, helpers)
    strip_global_filters()

    # convert_queries(Path(panther_analysis))
    run_ruff([Path(".")])  # noqa: PTH201

    if keep_only_modified_rules:
        delete_unmodified_panther_managed_rules()


if __name__ == "__main__":
    main()
