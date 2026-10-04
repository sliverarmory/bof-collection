#!/usr/bin/env python3
"""Validate the unsigned or signed ChromiumKeyDump Armory archive contents."""

import argparse
import json
from pathlib import Path
import re
import tarfile


EXPECTED = {
    "extension.json",
    "ChromiumKeyDump.x86.o",
    "ChromiumKeyDump.x64.o",
}
TARGETS = {
    ("windows", "386", "ChromiumKeyDump.x86.o"),
    ("windows", "amd64", "ChromiumKeyDump.x64.o"),
}
MACHINES = {
    "ChromiumKeyDump.x86.o": b"\x4c\x01",
    "ChromiumKeyDump.x64.o": b"\x64\x86",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--require-license", action="store_true")
    args = parser.parse_args()
    require(bool(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag)), "invalid tag")

    with tarfile.open(args.archive, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name.removeprefix("./") for member in members]
        require(len(names) == len(set(names)), "duplicate archive names")
        license_names = {
            name for name in names
            if name.upper().startswith(("LICENSE", "LICENCE", "COPYING")) and "/" not in name
        }
        require(set(names) == EXPECTED | license_names, f"unexpected archive inventory: {names}")
        if args.require_license:
            require(bool(license_names), "archive has no upstream license file")
        require(all(member.isfile() and not member.issym() and not member.islnk() for member in members),
                "archive must contain regular files only")
        payload = {name: archive.extractfile(member).read() for name, member in zip(names, members)}
        require(all(payload[name] for name in license_names), "archive contains an empty license file")

    manifest = json.loads(payload["extension.json"])
    require(manifest.get("version") == args.tag, "manifest version does not equal tag")
    require(manifest.get("repo_url") == "https://github.com/sliverarmory/bof-collection", "wrong repository")
    require(manifest.get("command_name") == "chromiumkeydump", "wrong command")
    require(manifest.get("bof_executor") == "reflektor", "BOF must select Reflektor")
    require("depends_on" not in manifest, "legacy loader dependency remains")
    require(manifest.get("entrypoint") == "go", "wrong BOF entrypoint")
    require({(entry["os"], entry["arch"], entry["path"]) for entry in manifest["files"]} == TARGETS,
            "manifest target map does not match objects")
    require(len(manifest.get("arguments", [])) == 1 and
            manifest["arguments"][0].get("name") == "browser" and
            manifest["arguments"][0].get("type") == "int" and
            manifest["arguments"][0].get("optional") is False,
            "BOF browser argument contract changed")
    for name, machine in MACHINES.items():
        require(payload[name][:2] == machine, f"{name} is not the expected COFF architecture")
        require(len(payload[name]) > 20, f"{name} is empty or truncated")
    print(f"validated {args.archive}: {args.tag}, 2 BOF objects, Reflektor routing")


if __name__ == "__main__":
    main()
