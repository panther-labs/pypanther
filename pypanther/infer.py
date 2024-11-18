import argparse
import subprocess
from typing import Tuple

from pkg_resources import resource_filename


def get_binary_path() -> str:
    return resource_filename("pypanther", "pantherlog")


def run(args: argparse.Namespace) -> Tuple[int, str]:
    cmd = [get_binary_path(), "infer"]

    if args.name:
        cmd.extend(["--name", args.name])
    if args.out:
        cmd.extend(["--out", args.out])
    if args.stream:
        cmd.extend(["--stream", args.stream])
    if args.skip_tests:
        cmd.append("--skip-tests")

    if args.extra_args:
        cmd.extend(args.extra_args)

    result = subprocess.run(cmd, check=False)
    return result.returncode, ""
