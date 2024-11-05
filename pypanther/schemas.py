import argparse
from typing import Tuple

def run(args: argparse.Namespace) -> Tuple[int, str]:
    print(args.path)
    return 0, ""
