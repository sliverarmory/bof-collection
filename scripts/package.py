#!/usr/bin/env python3
"""Stage the exact ChromiumKeyDump objects and a versioned Armory manifest."""

import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import tarfile


ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "chromiumkeydump"
OBJECTS = ("ChromiumKeyDump.x86.o", "ChromiumKeyDump.x64.o")


def add_member(archive: tarfile.TarFile, name: str, data: bytes, timestamp: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = timestamp
    archive.addfile(info, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--objects-dir", type=Path, required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag):
        parser.error("tag must have the exact form vMAJOR.MINOR.PATCH")
    manifest = json.loads((ROOT / "extension.json").read_text(encoding="utf-8"))
    manifest["version"] = args.tag
    if manifest.get("bof_executor") != "reflektor" or "depends_on" in manifest:
        parser.error("BOF manifest must select Reflektor without a loader dependency")
    if {entry["path"] for entry in manifest["files"]} != set(OBJECTS):
        parser.error("manifest object inventory differs from package inventory")
    manifest_bytes = (json.dumps(manifest, indent=4, ensure_ascii=False) + "\n").encode("utf-8")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = args.output_dir / f"{PACKAGE}.tar.gz"
    timestamp = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    with archive_path.open("wb") as output:
        with gzip.GzipFile(fileobj=output, filename="", mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                add_member(archive, "./extension.json", manifest_bytes, timestamp)
                for name in OBJECTS:
                    add_member(archive, f"./{name}", (args.objects_dir / name).read_bytes(), timestamp)
                for license_file in sorted(ROOT.iterdir()):
                    if license_file.is_file() and license_file.name.upper().startswith(
                        ("LICENSE", "LICENCE", "COPYING")
                    ):
                        add_member(archive, f"./{license_file.name}", license_file.read_bytes(), timestamp)
    print(archive_path)


if __name__ == "__main__":
    main()
