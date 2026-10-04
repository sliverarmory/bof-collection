#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$repo_root/build}"
mkdir -p "$output_dir"

source_file="$repo_root/ChromiumKeyDump/src/ChromiumKeyDump.cpp"
common_flags=(-std=c++17 -Os -Wall -Wextra -Werror -c)
"${CXX_X86:-i686-w64-mingw32-g++}" "${common_flags[@]}" \
  "$source_file" -o "$output_dir/ChromiumKeyDump.x86.o"
"${CXX_X64:-x86_64-w64-mingw32-g++}" "${common_flags[@]}" \
  "$source_file" -o "$output_dir/ChromiumKeyDump.x64.o"

file "$output_dir/ChromiumKeyDump.x86.o" "$output_dir/ChromiumKeyDump.x64.o"
