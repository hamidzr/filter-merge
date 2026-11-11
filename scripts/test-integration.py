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
import urllib.parse
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

    # fake AdGuard Home query log, newest first
    query_log: list[dict[str, object]] = []
    refresh_fetches: list[bytes] = []
    served_from: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            assert self.path == "/control/filtering/refresh", self.path
            self.rfile.read(int(self.headers["Content-Length"]))
            # AdGuard fetches its subscription while the refresh call is open
            with urllib.request.urlopen(served_from[0], timeout=10) as response:
                refresh_fetches.append(response.read())
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_GET(self) -> None:
            if self.path.startswith("/control/querylog"):
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                before = query.get("older_than", ["~"])[0]
                page = [item for item in query_log if str(item["time"]) < before]
                page = page[: int(query["limit"][0])]
                oldest = page[-1]["time"] if page else ""
                body = json.dumps({"data": page, "oldest": oldest}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
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

        def log_message(self, format: str, *args: object) -> None:
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

        exclude = root / "exclude.txt"
        exclude.write_text("# dead\nZ.example\nallowed.example\nwild.example\n")
        configure(["/a", "/b"], extra=f"exclude_file={exclude}\n")
        merge_ok()
        assert output.read_text().splitlines() == [
            "0.0.0.0 exact.example",
            "@@||allowed.example^$important",
            "||a.example^",
            "||wild.example^$dnsrewrite=NOERROR;A;0.0.0.0",
        ], output.read_text()
        results.append("exclude list drops plain rules only")

        state = root / "state"

        def entry(stamp: int, name: str, reason: str, cname: str = "") -> dict:
            answer = [{"type": "CNAME", "value": cname}] if cname else []
            return {
                "time": f"2026-01-01T00:00:{stamp:02d}Z" if stamp else name,
                "question": {"name": name, "type": "A"},
                "reason": reason,
                "answer": answer,
            }

        query_log[:] = [
            entry(2, "site.example", "NotFilteredNotFound", "cdn.wild.example."),
            entry(1, "A.example", "FilteredBlackList"),
        ]
        # older history than one shallow poll reads; a new store takes all of it
        query_log += [
            entry(0, f"1999-{number:04d}.test", "NotFilteredNotFound")
            for number in range(1200, 0, -1)
        ]
        served_from.append(f"http://127.0.0.1:{port}/filters.txt")
        configure(
            ["/a", "/b"],
            extra=f"state_dir={state}\nadguard_api={source_base}\nadaptive=1\n"
            "observe_interval_secs=1\nstate_flush_secs=1\nrefresh_secs=1\ncheck_secs=1\n",
        )
        counts.clear()
        process = subprocess.Popen(
            [str(binary), "serve", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            base = f"http://127.0.0.1:{port}"

            def stats() -> dict[str, str]:
                with urllib.request.urlopen(base + "/stats", timeout=2) as response:
                    lines = response.read().decode().splitlines()
                return dict(line.split("=", 1) for line in lines)

            def wait_for(check, what: str) -> None:
                for _ in range(200):
                    with contextlib.suppress(OSError, urllib.error.URLError):
                        if check():
                            return
                    time.sleep(0.05)
                raise AssertionError(what)

            wait_for(lambda: refresh_fetches, "no refresh after new names")
            adaptive = [
                "||a.example^",
                "||wild.example^$dnsrewrite=NOERROR;A;0.0.0.0",
            ]
            assert refresh_fetches[0].decode().splitlines() == adaptive
            assert stats()["observed_names"] == "1203", stats()
            # a repeated poll must not recount entries it already saw
            wait_for(lambda: int(stats()["polls"]) >= 3, "observer stopped")
            assert stats()["entries"] == "1202" and stats()["errors"] == "0", stats()
            query_log.insert(0, entry(3, "exact.example", "NotFilteredNotFound"))
            wait_for(lambda: len(refresh_fetches) >= 2, "new name did not refresh")
            assert refresh_fetches[-1].decode().splitlines() == [
                "0.0.0.0 exact.example",
                *adaptive,
            ]
            assert counts == {"/a": 1, "/b": 1}, counts
            # a new name that matches no rule must not spend a refresh
            query_log.insert(0, entry(4, "harmless.example", "NotFilteredNotFound"))
            wait_for(lambda: stats()["observed_names"] == "1205", "name not observed")
            polls = int(stats()["polls"])
            wait_for(lambda: int(stats()["polls"]) >= polls + 3, "observer stopped")
            assert stats()["refreshes"] == "2" and len(refresh_fetches) == 2, stats()
            wait_for(
                lambda: "exact.example\t" in (state / "seen.tsv").read_text(),
                "store not flushed",
            )
            store = (state / "seen.tsv").read_text()
            assert "a.example\t" in store and "cdn.wild.example\t" in store, store
            assert (state / "seen.tsv").stat().st_mode & 0o777 == 0o600
        finally:
            process.terminate()
            process.wait(timeout=5)
        configure(["/a", "/b"], extra=f"state_dir={state}\n")
        subprocess.run(
            [str(binary), "merge", str(config), str(output), "--adaptive"],
            check=True,
            capture_output=True,
            timeout=60,
        )
        assert output.read_text().splitlines() == ["0.0.0.0 exact.example", *adaptive]
        merge_ok()
        assert len(output.read_text().splitlines()) == 5
        results.append(
            "observer learns names and CNAMEs, adaptive list follows, cached candidates reused"
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
