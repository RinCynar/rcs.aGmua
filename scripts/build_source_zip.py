"""Create an architecture-labelled source ZIP for Linux releases."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INCLUDE = (
    "README.md",
    "LICENSE",
    "pyproject.toml",
    "rcs_agmua",
    "web",
    "src-tauri",
    "package.json",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default="linux")
    parser.add_argument("--arch", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    staging = args.output.parent / f"rcs-agmua-{args.platform}-{args.arch}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    try:
        for relative in INCLUDE:
            source = ROOT / relative
            destination = staging / relative
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        (staging / "VERSION").write_text(f"{args.version}\n", encoding="utf-8")
        shutil.make_archive(str(args.output.with_suffix("")), "zip", staging.parent, staging.name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
