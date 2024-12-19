import argparse
import ast
import functools
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from multiprocessing import Pool
from pathlib import Path
from typing import List, Optional, Set, TypedDict

from ast_comments import Comment, parse, unparse
from git import Repo
from ruamel.yaml import YAML

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


def to_id(class_name: str) -> str:
    # split on capital letters: "FooBarBaz" -> ["", "Foo", "", "Bar", "", "Baz", ""]
    splits = re.split(r"([A-Z][^A-Z]+)", class_name)
    # filter out empty splits: ["", "Foo", "", "Bar", "", "Baz", ""] -> ["Foo", "Bar", "Baz"]
    components = filter(len, splits)
    # join components with dots: ["Foo", "Bar", "Baz"] -> "Foo.Bar.Baz"
    id_ = ".".join(components)
    return id_


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
    ignored_checks = [
        "C403",
        "DTZ006",
        "E402",
        "E731",
        "E999",
        "EXE001",
        "F821",
        "FIX001",
        "PLR1722",
        "PLW0602",
        "PT027",
        "PTH122",
        "RET503",
        "RUF003",
        "TD001",
    ]
    subprocess.run(["ruff", "check", "--fix", "--ignore", ",".join(ignored_checks)] + list(paths), check=True)
    subprocess.run(["ruff", "format", "--silent"] + list(paths), check=True)


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


class DropClassAttributes(ast.NodeTransformer):
    """
    This node transformer takes a list of attribute names and deletes all assignments to them.

    A call like `DropClassAttributes(["A"]).visit(tree)` transforms this:
    ```
    class Foo:
        A = 1
        B = 2
    ```
    into this:
    ```
    class Foo:
        B = 2
    ```
    """

    def __init__(self, class_name: str, attribute_names: list[str]):
        super().__init__()
        self.class_name = class_name
        self.attribute_names = attribute_names

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        if node.name != self.class_name:
            return node

        new_body = [
            x
            for x in node.body
            if not (
                isinstance(x, ast.Assign)
                and len(x.targets) == 1
                and isinstance(x.targets[0], ast.Name)
                and x.targets[0].id in self.attribute_names
            )
        ]
        return ast.ClassDef(
            name=node.name,
            bases=[ast.Name(id=x) for x in node.bases],
            keywords=node.keywords,
            decorator_list=node.decorator_list,
            body=new_body,
        )


class RewriteClassDefinition(ast.NodeTransformer):
    """
    This node transformer refactors a class definition by changing its name and base names with the ones provided.

    A call like `RewriteClassDefinition("Bar", ["Baz"]).visit(tree)` transforms this:
    ```
    class Foo:
        A = 1
    ```
    into this:
    ```
    class Bar(Baz):
        A = 1
    ```
    """

    def __init__(self, class_name: str, new_class_name: str, base_names: list[str]):
        super().__init__()
        self.class_name = class_name
        self.new_class_name = new_class_name
        self.base_names = base_names

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST | None:
        if node.name != self.class_name:
            return node

        return ast.ClassDef(
            name=self.new_class_name,
            bases=[ast.Name(id=x) for x in self.base_names],
            keywords=node.keywords,
            decorator_list=[
                x
                for x in node.decorator_list
                if not (isinstance(x, ast.Name) and x.id == "panther_managed")  # exclude @panther_managed decorator
            ],
            body=node.body,
        )


class AddClassAttributes(ast.NodeTransformer):
    """
    This node transformer refactors a class definition by adding new attributes that correspond to its arguments.

    A call like `AddClassAttributes("Foo", {"bar": "baz", "foobar": 42}).visit(tree)` transforms this:
    ```
    class Foo:
        A = 1
    ```
    into this:
    ```
    class Foo:
        bar = "baz"
        foobar = 42
        A = 1
    ```
    """

    def __init__(self, class_name: str, attributes: dict[str, str | int | float | bool]):
        super().__init__()
        self.class_name = class_name
        self.attributes = attributes

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        if node.name != self.class_name:
            return node

        return ast.ClassDef(
            name=self.class_name,
            bases=node.bases,
            keywords=node.keywords,
            decorator_list=node.decorator_list,
            body=[
                *[
                    ast.Assign(targets=[ast.Name(id=k)], value=ast.Constant(value=v))
                    for k, v in self.attributes.items()
                ],
                *node.body,
            ],
        )


class AddImportFrom(ast.NodeTransformer):
    """
    This node transformer refactors a module by adding an import from statement based on the arguments.

    A call like `AddImportFrom("foo.bar", ["baz"]).visit(tree)` transforms this:
    ```
    import a
    from b import c

    class Foo:
        A = 1
    ```
    into this:
    ```
    from foo.bar import baz
    import a
    from b import c

    class Foo:
        A = 1
    ```
    """

    def __init__(self, from_module: str, names: list[str]):
        super().__init__()
        self.from_module = from_module
        self.names = names

    def visit_Module(self, node: ast.Module) -> ast.AST | None:
        return ast.Module(
            type_ignores=node.type_ignores,
            body=[
                ast.ImportFrom(
                    module=self.from_module,
                    names=[ast.alias(x) for x in self.names],
                ),
                *node.body,
            ],
        )


class DropClassMethods(ast.NodeTransformer):
    """
    This node transformer removes class methods from a specific class

    A call like `DropClassMethods("Foo", ["baz"]).visit(tree)` transforms this:
    ```
    class Foo:
        def baz():
            print("baz")

        def bar():
            print("bar")
    ```
    into this:
    ```
    class Foo:
        def bar():
            print("bar")
    ```
    """

    def __init__(self, class_name: str, names: list[str]):
        super().__init__()
        self.class_name = class_name
        self.names = names

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        if node.name != self.class_name:
            return node

        new_body = [x for x in node.body if not (isinstance(x, ast.FunctionDef) and x.name in self.names)]
        return ast.ClassDef(
            name=self.class_name,
            bases=node.bases,
            keywords=node.keywords,
            decorator_list=node.decorator_list,
            body=new_body,
        )


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
            # perror(f"AnalysisType must be 'global', not {gh['AnalysisType']}")
            continue

        helpers.add(Path(gh["Filename"]).stem)

    paths = []
    for p in (global_helpers_path).rglob("*.y*ml"):
        gh = YAML(typ="safe").load(p)

        if gh["AnalysisType"] != "global":
            # perror(f"AnalysisType must be 'global', not {gh['AnalysisType']}")
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
            # perror(f"AnalysisType must be 'datamodel', not {dm['AnalysisType']}")
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

    # print(f"Created __init__.py in {directory}")


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


def ast_compare(node1, node2):
    if type(node1) is not type(node2):
        return False

    if isinstance(node1, list):
        return len(node1) == len(node2) and all(ast_compare(n1, n2) for n1, n2 in zip(node1, node2))

    if isinstance(node1, ast.AST):
        for k, v in vars(node1).items():
            if k in ("lineno", "col_offset"):
                continue
            if not ast_compare(v, getattr(node2, k)):
                return False
        return True

    return node1 == node2


def clone_panther_analysis_main(output_dir: Path) -> None:
    if not output_dir.is_dir() or not output_dir.exists():
        raise ValueError(f"{output_dir} is not a directory")

    try:
        # git clone --depth 1 --branch main --single-branch https://github.com/panther-labs/panther-analysis.git output_dir
        _repo = Repo.clone_from(
            url="https://github.com/panther-labs/panther-analysis.git",
            to_path=output_dir,
            branch="main",
            depth=1,
            no_single_branch=False,
        )
    except Exception as exc:
        print(f"An error occurred while cloning the repository: {exc}")


def diff_rules_with_panther_analysis_main(
    panther_analysis: Path,
) -> tuple[list[tuple[list[str], str, str]], list[tuple[list[str], str, str, list[str]]], list[str]]:
    yaml_diff = []
    python_diff = []
    to_delete = []

    pa_main_rules = {}
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        clone_panther_analysis_main(output_dir)

        pa_main_rules_path = output_dir / "rules"
        for pa_main_python_path in pa_main_rules_path.glob("**/[A-Za-z]*.py"):
            pa_main_yaml_path = pa_main_python_path.with_suffix(".yml")
            with pa_main_yaml_path.open(mode="rb") as fy, pa_main_python_path.open(mode="rb") as fp:
                pa_main_yaml = YAML(typ="safe").load(fy)
                pa_main_python_code = ast.parse(fp.read())
            pa_main_rules[pa_main_yaml["RuleID"]] = (pa_main_yaml, pa_main_python_code)

    local_rules = {}
    local_rules_path = panther_analysis / "rules"
    for local_python_path in local_rules_path.glob("**/[A-Za-z]*.py"):
        local_yaml_path = local_python_path.with_suffix(".yml")
        with local_yaml_path.open(mode="rb") as fy, local_python_path.open(mode="rb") as fp:
            local_yaml = YAML(typ="safe").load(fy)
            local_python_code = ast.parse(fp.read())
        local_rules[local_yaml["RuleID"]] = (local_yaml, local_python_code, local_python_path.parent.stem)

    for id_, local_rule in local_rules.items():
        yaml, python = [], False

        if id_ not in pa_main_rules:
            continue

        pa_main_rule = pa_main_rules[id_]

        local_yaml, local_python_code, local_parent_dir = local_rule
        pa_main_yaml, pa_main_python_code = pa_main_rule

        # compare YAML
        for k, v in local_yaml.items():
            if v != pa_main_yaml[k]:
                yaml.append(k)

        # compare Python
        identical_function_names = []
        if not ast_compare(local_python_code, pa_main_python_code):
            python = True

            # identify identical functions; best effort
            if not isinstance(local_python_code, ast.Module) or not isinstance(pa_main_python_code, ast.Module):
                break
            local_functions = {x.name: x for x in local_python_code.body if isinstance(x, ast.FunctionDef)}
            pa_main_functions = {x.name: x for x in pa_main_python_code.body if isinstance(x, ast.FunctionDef)}
            for function_name in local_functions.keys():
                if ast_compare(local_functions[function_name], pa_main_functions[function_name]):
                    identical_function_names.append(function_name)

        if python:
            python_diff.append((yaml, local_yaml["Filename"], local_parent_dir, identical_function_names))
        elif yaml:
            yaml_diff.append((yaml, local_yaml["Filename"], local_parent_dir))

        if not python:
            # we only want to keep those for which we detected changes in python code
            # files for which we detected only yaml changes must be deleted as we create
            # overrides for them
            # files for which we haven't detected any changes at all must be deleted anyway
            to_delete.append(local_yaml["Filename"])

    return yaml_diff, python_diff, to_delete


def diff_helpers_with_panther_analysis_main(
    panther_analysis: Path,
) -> list[str]:
    to_delete = []

    pa_main_helpers = {}
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        clone_panther_analysis_main(output_dir)

        pa_main_helpers_path = output_dir / "global_helpers"
        for pa_main_yaml_path in pa_main_helpers_path.glob("**/[A-Za-z]*.y*ml"):
            if pa_main_yaml_path.stem.startswith("global_filter_"):
                continue
            with pa_main_yaml_path.open(mode="rb") as fy:
                pa_main_yaml = YAML(typ="safe").load(fy)

            pa_main_python_path = pa_main_yaml_path.parent.joinpath(pa_main_yaml["Filename"])
            with pa_main_python_path.open(mode="rb") as fp:
                pa_main_python_code = ast.parse(fp.read())

            pa_main_helpers[pa_main_yaml["GlobalID"]] = (pa_main_yaml, pa_main_python_code)

    local_helpers = {}
    local_helpers_path = panther_analysis / "global_helpers"
    for local_yaml_path in local_helpers_path.glob("**/[A-Za-z]*.y*ml"):
        if local_yaml_path.stem.startswith("global_filter_"):
            continue
        with local_yaml_path.open(mode="rb") as fy:
            local_yaml = YAML(typ="safe").load(fy)

        local_python_path = local_yaml_path.parent.joinpath(local_yaml["Filename"])
        with local_python_path.open(mode="rb") as fp:
            local_python_code = ast.parse(fp.read())

        local_helpers[local_yaml["GlobalID"]] = (local_yaml, local_python_code, local_python_path.parent.stem)

    for id_, local_helper in local_helpers.items():
        yaml, python = [], False

        if id_ not in pa_main_helpers:
            continue

        pa_main_helper = pa_main_helpers[id_]

        local_yaml, local_python_code, local_parent_dir = local_helper
        pa_main_yaml, pa_main_python_code = pa_main_helper

        # compare YAML
        for k, v in local_yaml.items():
            if v != pa_main_yaml[k]:
                yaml.append(k)

        # compare Python
        if not ast_compare(local_python_code, pa_main_python_code):
            python = True

        if not python and not yaml:
            to_delete.append(local_yaml["Filename"])

    return to_delete


class Overrides(TypedDict):
    imports: list[ast.ImportFrom]
    keywords: dict[str, list[ast.keyword]]


def refactor_yaml_only_modified_rules(
    rules_path: Path,
    overrides_path: Path,
    diff: list[tuple[list[str], str, str]],
) -> None:
    # yaml changed but python didn't, keep CHANGED class attributes in an override
    overrides: dict[str, Overrides] = {}
    for yaml_keys, filename, rules_dir in diff:
        module = rules_dir.removesuffix("_rules")
        rule_path = rules_path / module / filename

        if not rule_path.exists():
            # account for deprecated rules
            continue

        with rule_path.open(mode="rb") as fp:
            code = ast.parse(fp.read())

        # get class name
        class_definition = [x for x in code.body if isinstance(x, ast.ClassDef)][0]

        if module not in overrides:
            overrides[module] = {"imports": [], "keywords": {}}

        if "imports" not in overrides[module]:
            overrides[module]["imports"] = []

        overrides[module]["imports"].append(
            ast.ImportFrom(module=f"pypanther.rules.{module}", names=[ast.alias(class_definition.name)]),
        )

        if "keywords" not in overrides[module]:
            overrides[module]["keywords"] = {}

        if class_definition.name not in overrides[module]["keywords"]:
            overrides[module]["keywords"][class_definition.name] = []

        for k in yaml_keys:
            value = [
                x
                for x in class_definition.body
                if (
                    isinstance(x, ast.Assign)
                    and len(x.targets) == 1
                    and isinstance(x.targets[0], ast.Name)
                    and x.targets[0].id == convert_rule_attribute_name(k)
                )
            ][0].value
            overrides[module]["keywords"][class_definition.name].append(
                ast.keyword(value=value, arg=convert_rule_attribute_name(k)),
            )

    if not overrides:
        return

    overrides_path.mkdir(exist_ok=True)
    overrides_path.joinpath("__init__.py").touch()

    for module, v in overrides.items():
        imports = v["imports"]
        keywords = v["keywords"]

        overrides_module = ast.Module(
            body=[
                ast.ImportFrom(
                    module="pypanther",
                    names=[
                        ast.alias("Rule"),
                        ast.alias("RuleTest"),
                        ast.alias("Severity"),
                        ast.alias("LogType"),
                        ast.alias("RuleMock"),
                        ast.alias("panther_managed"),
                    ],
                ),
                *imports,
                ast.FunctionDef(
                    name="apply_overrides",
                    decorator_list=[],
                    args=ast.arguments(
                        posonlyargs=[],
                        args=[],
                        vararg=None,
                        kwonlyargs=[],
                        kw_defaults=[],
                        kwarg=None,
                        defaults=[],
                    ),
                    returns=None,
                    body=[
                        ast.Expr(
                            value=ast.Call(
                                func=ast.Attribute(value=ast.Name(id=cdef_name), attr="override"),
                                keywords=[*keywords],
                                args=[],
                            ),
                        )
                        for cdef_name, keywords in keywords.items()
                    ],
                ),
            ],
            type_ignores=[],
        )

        with (overrides_path / Path(module).with_suffix(".py")).open(mode="w") as f:
            f.write(ast.unparse(ast.fix_missing_locations(overrides_module)))


def refactor_python_modified_rules(rules_path: Path, diff: list[tuple[list[str], str, str, list[str]]]) -> None:
    # at least python changed, will need to keep the file but delete the UNCHANGED class attributes
    for yaml_keys, filename, rules_dir, identical_function_names in diff:
        module = rules_dir.removesuffix("_rules")
        rule_path = rules_path / module / filename

        if not rule_path.exists():
            # account for deprecated rules
            continue

        with rule_path.open(mode="rb") as fp:
            code = ast.parse(fp.read())

        # get class name
        class_definition = [x for x in code.body if isinstance(x, ast.ClassDef)][0]
        new_class_definition_name = class_definition.name + "Custom"
        new_class_definition_id = to_id(new_class_definition_name)

        attributes_to_drop = [
            x.targets[0].id
            for x in class_definition.body
            if (
                isinstance(x, ast.Assign)
                and len(x.targets) == 1
                and isinstance(x.targets[0], ast.Name)
                and x.targets[0].id not in set(convert_rule_attribute_name(y) for y in yaml_keys)
            )
        ]
        code = DropClassAttributes(class_definition.name, attributes_to_drop).visit(code)
        code = RewriteClassDefinition(
            class_definition.name,
            new_class_definition_name,
            [class_definition.name],
        ).visit(code)
        code = AddClassAttributes(new_class_definition_name, {"id": new_class_definition_id}).visit(code)
        code = AddImportFrom(
            "pypanther.rules." + module,
            [class_definition.name],
        ).visit(code)
        code = DropClassMethods(new_class_definition_name, identical_function_names).visit(code)

        with rule_path.open(mode="w") as fp:
            fp.write(ast.unparse(ast.fix_missing_locations(code)))


def delete_rules(rules_path: Path, to_delete: list[str]) -> None:
    for filename in to_delete:
        if filename.startswith("sublime_rules_deleted_or_deactivated"):
            # for this case, when converting to pypanther we have decided to turn
            # sublime_rules_deleted_or_deactivated.py to sublime_deleted_or_deactivated.py
            filename = filename.replace("_rules", "")

        possible_paths = list(rules_path.rglob(f"**/{filename}"))

        if len(possible_paths) > 1:
            raise Exception(f"multiple paths for {filename}")

        if len(possible_paths) == 0:
            # possibly deprecated rule
            continue

        path = possible_paths[0]
        path.unlink()
        if not any(path.parent.iterdir()):
            path.parent.rmdir()

    # delete empty directories or directories that contain only __init__.py files
    for root, dirs, files in os.walk(str(rules_path), topdown=False):
        if len(dirs) == 0 and len(files) == 1 and files[0] == "__init__.py":
            Path(os.path.join(root, files[0])).unlink()
        for name in dirs:
            directory = Path(os.path.join(root, name))
            if not any(directory.iterdir()):
                # directory is empty
                directory.rmdir()

    # if the rules directory itself is empty, delete it
    if not any(rules_path.iterdir()):
        rules_path.rmdir()


def delete_helpers(helpers_path: Path, to_delete: list[str]) -> None:
    for filename in to_delete:
        fixed_filename = filename.replace("panther_", "").replace("_helpers", "")

        possible_paths = list(helpers_path.rglob(f"**/{fixed_filename}"))

        if len(possible_paths) > 1:
            raise Exception(f"multiple paths for {fixed_filename}")

        if len(possible_paths) == 0:
            # possibly deprecated rule
            continue

        path = possible_paths[0]
        path.unlink()
        if not any(path.parent.iterdir()):
            path.parent.rmdir()

    # delete empty directories or directories that contain only __init__.py files
    for root, dirs, files in os.walk(str(helpers_path), topdown=False):
        if len(dirs) == 0 and len(files) == 1 and files[0] == "__init__.py":
            Path(os.path.join(root, files[0])).unlink()
        for name in dirs:
            directory = Path(os.path.join(root, name))
            if not any(directory.iterdir()):
                # directory is empty
                directory.rmdir()

    # if the helpers directory itself is empty, delete it
    if not any(helpers_path.iterdir()):
        helpers_path.rmdir()


def delete_data_models(data_models_path: Path) -> None:
    shutil.rmtree(data_models_path)


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("panther_analysis_path", type=Path)
    parser.add_argument("--keep-all-rules", default=False, action="store_true")
    parser.add_argument("--verbose", default=False, action="store_true")
    return parser


def convert(args: argparse.Namespace) -> tuple[int, str]:
    panther_analysis = args.panther_analysis_path
    keep_only_modified_rules = not args.keep_all_rules

    if hasattr(args, "cwd_must_be_empty") and args.cwd_must_be_empty and any(Path("./").iterdir()):
        return 1, "current working directory must be empty"

    try:
        helpers = convert_global_helpers(panther_analysis)
        convert_data_models(panther_analysis, helpers)
        convert_rules(panther_analysis, helpers)
        strip_global_filters()
        # convert_queries(Path(panther_analysis))

        if keep_only_modified_rules:
            rules_path = Path("./pypanther/rules/")
            overrides_path = Path("./pypanther/overrides")
            yaml_diff, python_diff, rules_to_delete = diff_rules_with_panther_analysis_main(panther_analysis)
            refactor_yaml_only_modified_rules(rules_path, overrides_path, yaml_diff)
            refactor_python_modified_rules(rules_path, python_diff)
            delete_rules(Path("./pypanther/rules/"), rules_to_delete)
            helpers_to_delete = diff_helpers_with_panther_analysis_main(panther_analysis)
            delete_helpers(Path("./pypanther/helpers/"), helpers_to_delete)
            delete_data_models(Path("./pypanther/data_models/"))

        # "pypanther" is the default output directory; we only to run ruff on those
        run_ruff([Path("./pypanther/")])
    except Exception as exc:
        if hasattr(args, "verbose") and args.verbose:
            traceback.print_exception(exc)
        return 1, "conversion failed"

    Path("./pypanther/__init__.py").touch()

    if hasattr(args, "pypanther_directory_name") and args.pypanther_directory_name:
        shutil.move(Path("./pypanther/"), Path(f"./{args.pypanther_directory_name}/"))

    return 0, ""


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    return_code, error = convert(args)
    if return_code > 0:
        print(error)

    return return_code


if __name__ == "__main__":
    sys.exit(main())
