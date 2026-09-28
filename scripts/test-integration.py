#!/usr/bin/env -S uv run --script
"""Exercise downloader and HTTP service against controlled source lists."""

import concurrent.futures
import contextlib
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    binary = pathlib.Path(sys.argv[1]).resolve()
    counts: dict[str, int] = {}
    payloads: dict[str, bytes] = {
        "/a": b"! title\n[Adblock Plus 2.0]\n||z.example^\n||a.example^\n"
        b"@@||allowed.example^$important\n0.0.0.0 exact.example\n",
        "/b": b"# comment\n||a.example^\r\n||z.example^\n"
        b"||wild.example^$dnsrewrite=NOERROR;A;0.0.0.0\n",
        "/empty": b"! only comments\n",
        "/html": b"<!DOCTYPE html>\n<html>bad upstream</html>\n",
        "/slow": b"||slow.example^\n",
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            counts[self.path] = counts.get(self.path, 0) + 1
            if self.path == "/million":
                self.send_response(200)
                self.end_headers()
                for first in range(0, 1_000_000, 1000):
                    chunk = "".join(
                        f"||d{number:07d}.example^\n"
                        for number in range(first + 999, first - 1, -1)
                    )
                    self.wfile.write(chunk.encode())
                return
            if self.path not in payloads:
                self.send_error(404)
                return
            if self.path == "/slow":
                time.sleep(0.5)
            body = payloads[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source_base = f"http://127.0.0.1:{server.server_port}"
    results: list[str] = []
    with tempfile.TemporaryDirectory(prefix="filter-merge-test-") as directory:
        root = pathlib.Path(directory)
        config = root / "config"
        work = root / "work"
        output = root / "out.txt"
        port = free_port()

        def configure(paths: list[str], chunk: int = 65536, extra: str = "") -> None:
            config.write_text(
                f"listen=127.0.0.1:{port}\nwork_dir={work}\nchunk_bytes={chunk}\n"
                "max_input_bytes=33554432\nmax_output_bytes=33554432\n"
                "max_line_bytes=8192\nmax_run_files=128\n"
                "download_timeout_secs=5\nbuild_timeout_secs=45\n"
                + extra
                + "".join(f"url={source_base}{path}\n" for path in paths)
            )

        def merge_ok() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [str(binary), "merge", str(config), str(output)],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            )

        configure(["/a", "/b"])
        abandoned = work / "build-999999999-0"
        abandoned.mkdir(parents=True)
        (abandoned / "stale").write_text("interrupted build")
        merge_ok()
        assert not abandoned.exists()
        expected = sorted(
            {
                "||z.example^",
                "||a.example^",
                "@@||allowed.example^$important",
                "0.0.0.0 exact.example",
                "||wild.example^$dnsrewrite=NOERROR;A;0.0.0.0",
            }
        )
        actual = [
            line for line in output.read_text().splitlines() if not line.startswith("!")
        ]
        assert actual == expected, (actual, expected)
        saved = output.read_bytes()
        results.append(
            "exact syntax preserved; sorted and deduplicated; abandoned staging recovered"
        )

        for path in ("/missing", "/empty", "/html"):
            configure(["/a", path])
            result = subprocess.run(
                [str(binary), "merge", str(config), str(output)],
                capture_output=True,
                timeout=15,
                check=False,
            )
            assert result.returncode != 0, path
            assert output.read_bytes() == saved, path
            assert not list(work.glob("build-*")), path
        results.append(
            "failed, empty, HTML sources preserve previous output and clean staging"
        )

        configure(["/million"], chunk=2 * 1024 * 1024)
        started = time.monotonic()
        merge_ok()
        previous = ""
        lines = 0
        with output.open() as handle:
            for line in handle:
                if line.startswith("!"):
                    continue
                assert line > previous
                previous = line
                lines += 1
        assert lines == 1_000_000, lines
        results.append(
            f"million-line chunked merge passed in {time.monotonic() - started:.2f}s"
        )

        configure(["/slow"])
        process = subprocess.Popen(
            [str(binary), "serve", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    with urllib.request.urlopen(
                        base + "/healthz", timeout=1
                    ) as response:
                        metadata = response.read().decode()
                    assert (
                        "filter-merge" in metadata
                        and subprocess.check_output(
                            [str(binary), "--version"], text=True
                        ).split()[0]
                        in metadata
                    )
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise AssertionError("service did not start")
            request = urllib.request.Request(base + "/filters.txt", method="HEAD")
            with urllib.request.urlopen(request, timeout=2) as response:
                assert response.read() == b""
            assert counts.get("/slow", 0) == 0
            gate = threading.Barrier(2)

            def fetch() -> bytes:
                gate.wait(timeout=3)
                with urllib.request.urlopen(
                    base + "/filters.txt", timeout=10
                ) as response:
                    return response.read()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(fetch) for _ in range(2)]
                responses = [future.result(timeout=15) for future in futures]
            assert responses[0] == responses[1]
            assert b"||slow.example^" in responses[0]
            assert counts["/slow"] == 1, counts
            with urllib.request.urlopen(base + "/filters.txt", timeout=10) as response:
                response.read()
            assert counts["/slow"] == 2, counts
            results.append(
                "localhost HTTP, metadata, cheap HEAD, shared concurrent build, rebuild each GET"
            )
        finally:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)
            if process.poll() is None:
                process.kill()
                process.wait()
    server.shutdown()
    print(json.dumps({"passed": results}, indent=2))


if __name__ == "__main__":
    main()
