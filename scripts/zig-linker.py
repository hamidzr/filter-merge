#!/usr/bin/env python3
"""Link Rust with Zig's musl archives and LLD, keeping ARM64 erratum fixes."""

import os
import pathlib
import shlex
import sys


def main() -> None:
    toolchain = pathlib.Path(__file__).resolve().parent
    lines = (toolchain / "probe-link.txt").read_text().splitlines()
    command = next(line for line in reversed(lines) if line.startswith("ld.lld "))
    probe_args = shlex.split(command)
    archives = [value for value in probe_args if value.endswith(".a")]
    startup = next(value for value in probe_args if value.endswith("/crt1.o"))
    arguments = ["ld.lld", "-m", "aarch64linux", startup]
    for value in sys.argv[1:]:
        if value in {
            "crt1.o",
            "crti.o",
            "crtbegin.o",
            "crtend.o",
            "crtn.o",
            "-nostartfiles",
            "-nodefaultlibs",
            "-lc",
            "-lunwind",
        }:
            continue
        if value.startswith("-Wl,"):
            arguments.extend(value[4:].split(","))
        else:
            arguments.append(value)
    arguments.extend(archives)
    binary = str(toolchain / "zig" / "zig")
    os.execv(binary, [binary, *arguments])


if __name__ == "__main__":
    main()
