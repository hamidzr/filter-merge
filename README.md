# filter-merge

Small Rust server that merges DNS filter lists for AdGuard Home with bounded
sorting buffers. AdGuard fetches one localhost URL; the server downloads your
configured sources, sorts chunks on disk, removes exact duplicate rules across
lists, and returns one filter list. AdGuard owns the update schedule. No cron,
Nginx, database, or Rust dependencies. Runtime downloads use `curl`.

Useful on routers where overlapping subscriptions waste resources. This is an
independent companion, not an AdGuard product or a replacement filtering engine.
It does not eliminate AdGuard's own parsing/indexing memory or update spikes.

## One-command OpenWrt setup

Prebuilt static Linux binaries support ARM64 (`aarch64`) and AMD64 (`x86_64`).
Other router architectures still require a source build. On OpenWrt, run as root
with curl and CA certificates installed:

```sh
curl -fsSL https://github.com/hamidzr/filter-merge/releases/download/v0.1.1/install.sh | sh -s -- --url https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
```

Repeat `--url URL` for each of your existing subscriptions. Installer verifies
binary SHA-256, installs the procd boot service, and uses `/overlay` for staging.
Then add `http://127.0.0.1:3054/filters.txt` in AdGuard's DNS blocklists. Once it
downloads successfully, disable the original subscriptions included in the merger.
Installer does not edit AdGuard settings. Without `--url`, a new installation
uses only the default AdGuard DNS source. Existing config is preserved on upgrades;
edit `/etc/filter-merge.conf` and restart to change sources.

For inspection before execution, download `install.sh`, read it, then run it.
For other Linux systems, append `--download-only ./filter-merge-bin` to download
verified files without installing a service. Configure your OS service manager
as described below. Native macOS builds remain available from source.

GitHub Actions builds and tests both architectures before publishing tag releases.
Release assets include the installer, archives, and `SHA256SUMS`. Checksums detect
corruption; they are not an independent signature of the GitHub publisher.

## Quick start (Linux or macOS)

Requires Rust 1.89+, curl, and a Unix filesystem. Windows is not supported.

```sh
git clone https://github.com/hamidzr/filter-merge.git
cd filter-merge
cargo build --locked --release
cp filter-merge.conf filter-merge.local.conf
```

Edit `filter-merge.local.conf`: replace the `url=` entries with your existing DNS
blocklist subscriptions. Set `work_dir` to an absolute, writable directory on
real disk. For example, `/var/lib/filter-merge/work` on Linux; on macOS use a
writable directory under your home folder. Then run:

```sh
./target/release/filter-merge serve filter-merge.local.conf
curl -f http://127.0.0.1:3054/filters.txt -o merged.txt
```

This foreground command is useful for verification. For permanent operation use
OpenWrt procd below, or your OS service manager. Run under an unprivileged account
with write access to the work directory when possible.

In AdGuard Home, open **Filters > DNS blocklists**, add a custom list named
`Merged filters`, and set its URL to `http://127.0.0.1:3054/filters.txt`. After a
successful download, disable the original subscriptions included in the merger.
Keep them configured for easy rollback. Set AdGuard's filter update interval to
your preference, for example seven days. Each GET rebuilds; requests queued during
a build share its result. Changing configuration requires restarting the server.

Server and AdGuard must share the same network namespace. With containers,
`127.0.0.1` means that container; run them together or use host networking on
Linux. The server deliberately rejects non-loopback listen addresses.

## Configuration

Plain `key=value` file. Blank lines and `#` comments are allowed. Unknown keys
are rejected. The example explicitly selects the limits below; omitted settings
use the defaults in `src/lib.rs` (notably 64 MiB input/output and 20s per source).

| Key | Example value | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:3054` | Loopback address and port |
| `work_dir` | `/overlay/filter-merge/work` | Absolute staging path on disk |
| `url` | `https://example.org/filter.txt` | Repeat for each source; HTTP/HTTPS only |
| `chunk_bytes` | `2097152` | Sorting arena size, 2 MiB |
| `max_input_bytes` | `33554432` | Aggregate downloaded text cap, 32 MiB |
| `max_output_bytes` | `33554432` | Merged output cap, 32 MiB |
| `max_line_bytes` | `8192` | Maximum rule length |
| `max_sources` | `32` | Maximum source count |
| `max_run_files` | `128` | Maximum sorted chunks |
| `download_timeout_secs` | `15` | Per-source timeout |
| `build_timeout_secs` | `55` | Whole-build deadline |

Downloads are sequential. curl verifies HTTPS certificates. Ensure the router
has curl and CA certificates installed. Sources must return plain text;
compressed transfers are not requested. Use trusted DNS filter lists, not
arbitrary browser filter lists. No credentials are needed for public lists.

## Semantics and failure handling

Exact rule bytes are preserved, including hosts entries, exceptions, modifiers,
and surrounding whitespace. CRLF becomes LF. Blank lines, comments, and Adblock
Plus headers are removed. Output is sorted. Different syntax for the same domain
is not collapsed, and redundant subdomain rules are not semantically compressed.
Include directives in comments are not expanded; use fully materialized lists.
Per-list attribution and individual AdGuard toggles become one subscription.

Empty, HTML, failed, oversized, or timed-out sources fail the whole build. HTTP
returns 502 before any filter content; AdGuard can retain its previously downloaded
list. No partially merged response is published. Normal staging is deleted after
serving; the next build cleans abandoned staging after a killed process. A work
lock prevents overlapping builds in one work directory.

Buffers are bounded, **total RSS is not hard-capped at 20 MiB**. RSS includes curl,
libc, and other overhead. Staging occupies roughly twice the input size on disk;
CLI publication can require a third copy plus existing output. Disk exhaustion
fails the build. On OpenWrt, `/tmp` is usually RAM-backed: use `/overlay` or mounted
storage to avoid moving the staging cost into RAM. Flash writes occur on each
fetch; frequent manual fetches increase wear. No permanent server-side cache is
kept; AdGuard stores its downloaded copy.

The service is single-threaded. Health checks wait for an active build. It is
intended for a local AdGuard process, not a public HTTP endpoint.

## OpenWrt installation

Build on your workstation for your router's actual architecture. For an ARM64
router, a standard Rust musl cross toolchain can build with:

```sh
rustup target add aarch64-unknown-linux-musl
# Requires an appropriate musl linker configured for this target.
cargo build --locked --release --target aarch64-unknown-linux-musl
```

`scripts/build-router.sh` provides an alternative tested on macOS ARM64 with
Homebrew Rust and bundled rust-src. It downloads checksum-pinned Zig 0.15.2 and
builds a static ARM64 binary. This helper is specifically for that workstation
and target; it does not support every OpenWrt architecture.

```sh
bash scripts/build-router.sh
scp target/aarch64-unknown-linux-musl/release/filter-merge root@ROUTER:/usr/bin/filter-merge
scp filter-merge.conf root@ROUTER:/etc/filter-merge.conf
scp openwrt/filter-merge.init root@ROUTER:/etc/init.d/filter-merge
ssh root@ROUTER 'chmod 755 /usr/bin/filter-merge /etc/init.d/filter-merge'
```

Edit `/etc/filter-merge.conf` with your sources, then on the router:

```sh
/etc/init.d/filter-merge enable
/etc/init.d/filter-merge start
curl -f http://127.0.0.1:3054/filters.txt -o /dev/null
```

Then configure AdGuard as above. The procd script starts at priority 98; ensure
AdGuard starts later on your installation. For upgrades that preserve settings,
add these paths to `/etc/sysupgrade.conf` if not already present:

```text
/usr/bin/filter-merge
/etc/init.d/filter-merge
/etc/filter-merge.conf
```

Check logs with `logread -e filter-merge`. Restart after configuration edits with
`/etc/init.d/filter-merge restart`. To roll back, enable the original AdGuard
subscriptions, update them successfully, then disable the merged subscription
and stop/disable this service. No automated AdGuard YAML editing is required.

## CLI and endpoints

```sh
filter-merge --version
filter-merge serve CONFIG
filter-merge merge CONFIG OUTPUT
```

CLI export replaces OUTPUT atomically after success. `/filters.txt` builds and
serves the list. `/healthz` and `/version` expose health/build identity without
fetching sources. HEAD does not rebuild. Version includes semver, Git revision,
and UTC build date. Optional `SOURCE_DATE_EPOCH` supplies reproducible build time.

## Tests and measurements

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
python3 scripts/test-integration.py target/release/filter-merge
```

Integration tests use local HTTP fixtures: cross-chunk deduplication, exact rule
preservation, failed/empty/HTML sources, atomic output retention, abandoned staging,
one million reverse-ordered rules, HEAD, and concurrent fetch coalescing.
`just check` additionally requires shfmt and shellcheck; `just test` uses uv with
Python 3.13. `just install` installs the native CLI through Cargo.

Measured on an ARM64 GL-MT3000 router in September 2026:

- Original custom size-optimized static binary approximately 211 KiB.
- Published v0.1.1 ARM64 CI binary: 462,808 bytes (452 KiB), verified on the router.
- Five sources: 12.64 MB input, 430,505 unique rules, 10.22 MB output, 5.35s rebuild.
- Sampled combined server plus curl peak 11.3 MiB; includes HTTP client curl.
- One million rules / 20 MB sorted output matched independently generated hash.

Recorded five-list comparison before deployment (same snapshot, exact rules):

| Metric | Recorded result |
| --- | --- |
| Rule occurrences across five lists | 545,734 |
| Unique exact rules | 434,948 |
| Redundant occurrences removed | 110,786 (20.3%) |
| AdGuard RSS before activation | 139,948 KiB (136.7 MiB) |
| AdGuard RSS immediately after activation and restart | 97,272 KiB (95.0 MiB) |
| Immediate observed RSS decrease | 42,676 KiB (41.7 MiB), 30.5% |
| Later warmed AdGuard RSS | 122,580 KiB (119.7 MiB) |
| Later observed RSS decrease from pre-activation sample | 17,368 KiB (17.0 MiB), 12.4% |

Post-activation samples had no swap. The historical duplicate snapshot and live
five-source build above were captured at different times; upstream list changes
explain their different unique-rule counts. The 20.3% figure counts redundant
exact rule occurrences, not semantically equivalent domains.

Memory/workload figures above used the original custom build; release CI uses
the standard Rust musl library, so its RSS has not been remeasured. These are
workload measurements, not universal memory guarantees. AdGuard was
also restarted, so observed AdGuard RSS changes do not isolate deduplication's
benefit. Measure on your own lists and hardware.

For a richer upstream tool, see AdGuard's
[Hostlist Compiler](https://github.com/AdguardTeam/HostlistCompiler), which supports
normalization and transformations. This project focuses on exact deduplication
with small bounded sorting buffers.

## License

MIT. Source filter lists retain their own licenses; this project's license does
not grant redistribution rights to their contents.
