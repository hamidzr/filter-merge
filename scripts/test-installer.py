#!/usr/bin/env python3
"""Check release download, architecture detection, and checksum failure."""

import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main() -> None:
    project = Path(__file__).resolve().parent.parent
    binary = (
        Path(os.environ.get("CARGO_TARGET_DIR", project / "target"))
        / "release/filter-merge"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        mock = root / "bin"
        mock.mkdir()
        (mock / "uname").write_text(
            '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo aarch64;; esac\n'
        )
        (mock / "curl").write_text("""#!/bin/sh
while [ "$#" -gt 0 ]; do
 case "$1" in
  https://*) url=$1; shift;;
  -o) output=$2; shift 2;;
  *) shift;;
 esac
done
cp "$FIXTURE/${url##*/}" "$output"
""")
        for file in mock.iterdir():
            file.chmod(0o755)
        archive = root / "filter-merge-v0.1.1-aarch64-linux-musl.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for path, name in [
                (binary, "filter-merge"),
                (project / "filter-merge.conf", "filter-merge.conf"),
                (project / "openwrt/filter-merge.init", "filter-merge.init"),
            ]:
                tar.add(path, arcname=name)
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        checks = root / "SHA256SUMS"
        checks.write_text(f"{checksum}  {archive.name}\n")
        env = dict(os.environ, PATH=f"{mock}:{os.environ['PATH']}", FIXTURE=str(root))
        output = root / "output"
        command = [
            "sh",
            str(project / "scripts/install.sh"),
            "--download-only",
            str(output),
        ]
        subprocess.run(command, env=env, check=True)
        assert (output / "filter-merge").read_bytes() == binary.read_bytes()
        checks.write_text(f"{'0' * 64}  {archive.name}\n")
        failed = root / "failed"
        result = subprocess.run(
            command[:-1] + [str(failed)], env=env, capture_output=True
        )
        assert result.returncode != 0 and not failed.exists()
        result = subprocess.run(
            command + ["--url", "file:///etc/passwd"], env=env, capture_output=True
        )
        assert result.returncode != 0
        print(
            "installer: verified download, checksum rejection, invalid source rejection passed"
        )


if __name__ == "__main__":
    main()
