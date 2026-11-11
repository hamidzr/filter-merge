pub mod adaptive;

use adaptive::{NameSet, Observer, Seen};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("BUILD_REVISION"),
    " ",
    env!("BUILD_DATE"),
    ")"
);
type Result<T> = std::result::Result<T, String>;
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub work_dir: PathBuf,
    pub chunk_bytes: usize,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_line_bytes: usize,
    pub max_sources: usize,
    pub max_run_files: usize,
    pub download_timeout_secs: u64,
    pub build_timeout_secs: u64,
    pub urls: Vec<String>,
    /// Domains whose plain rules are dropped from the output.
    pub exclude_file: Option<PathBuf>,
    /// Holds the observed-domain store; required for observation.
    pub state_dir: Option<PathBuf>,
    /// AdGuard Home base URL; setting it turns observation on.
    pub adguard_api: Option<String>,
    pub glinet_session: bool,
    pub observe_interval_secs: u64,
    pub state_flush_secs: u64,
    /// Serve only rules that could match an observed name.
    pub adaptive: bool,
    pub adaptive_min_queries: u64,
    /// Stop serving rules for names not seen for this many days; 0 never stops.
    pub adaptive_max_age_days: u32,
    pub check_secs: u64,
    pub seen_max_age_days: u32,
    pub seen_max_entries: usize,
    pub candidate_max_age_hours: u64,
    pub refresh_secs: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3054".parse().unwrap(),
            work_dir: "/tmp/filter-merge".into(),
            chunk_bytes: 2_097_152,
            max_input_bytes: 67_108_864,
            max_output_bytes: 67_108_864,
            max_line_bytes: 8192,
            max_sources: 32,
            max_run_files: 128,
            download_timeout_secs: 20,
            build_timeout_secs: 55,
            urls: Vec::new(),
            exclude_file: None,
            state_dir: None,
            adguard_api: None,
            glinet_session: false,
            observe_interval_secs: 60,
            state_flush_secs: 3600,
            adaptive: false,
            adaptive_min_queries: 1,
            adaptive_max_age_days: 90,
            check_secs: 300,
            seen_max_age_days: 0,
            seen_max_entries: 200_000,
            candidate_max_age_hours: 168,
            refresh_secs: 21_600,
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut input = String::new();
        File::open(path)
            .map_err(|_| "cannot read configuration")?
            .take(65537)
            .read_to_string(&mut input)
            .map_err(|_| "cannot read configuration")?;
        if input.len() > 65536 {
            return Err("configuration exceeds 64 KiB".into());
        }
        Self::parse(&input)
    }
    pub fn parse(input: &str) -> Result<Self> {
        let mut config = Self::default();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or("configuration requires key=value")?;
            let value = value.trim();
            macro_rules! number {
                ($field:ident) => {
                    config.$field = value
                        .parse()
                        .map_err(|_| concat!("invalid ", stringify!($field)))?
                };
            }
            let flag = || match value {
                "0" => Ok(false),
                "1" => Ok(true),
                _ => Err("flags must be 0 or 1"),
            };
            match key.trim() {
                "listen" => config.listen = value.parse().map_err(|_| "invalid listen address")?,
                "work_dir" => config.work_dir = value.into(),
                "chunk_bytes" => number!(chunk_bytes),
                "max_input_bytes" => number!(max_input_bytes),
                "max_output_bytes" => number!(max_output_bytes),
                "max_line_bytes" => number!(max_line_bytes),
                "max_sources" => number!(max_sources),
                "max_run_files" => number!(max_run_files),
                "download_timeout_secs" => number!(download_timeout_secs),
                "build_timeout_secs" => number!(build_timeout_secs),
                "exclude_file" => config.exclude_file = Some(value.into()),
                "state_dir" => config.state_dir = Some(value.into()),
                "adguard_api" => config.adguard_api = Some(value.into()),
                "glinet_session" => config.glinet_session = flag()?,
                "observe_interval_secs" => number!(observe_interval_secs),
                "state_flush_secs" => number!(state_flush_secs),
                "adaptive" => config.adaptive = flag()?,
                "adaptive_min_queries" => number!(adaptive_min_queries),
                "adaptive_max_age_days" => number!(adaptive_max_age_days),
                "check_secs" => number!(check_secs),
                "seen_max_age_days" => number!(seen_max_age_days),
                "seen_max_entries" => number!(seen_max_entries),
                "candidate_max_age_hours" => number!(candidate_max_age_hours),
                "refresh_secs" => number!(refresh_secs),
                "url" => {
                    if !(value.starts_with("https://") || value.starts_with("http://"))
                        || value.chars().any(char::is_whitespace)
                    {
                        return Err("source must be an HTTP(S) URL without whitespace".into());
                    }
                    config.urls.push(value.into());
                }
                _ => return Err("unknown configuration key".into()),
            }
        }
        if !config.listen.ip().is_loopback() {
            return Err("listen must be a loopback address".into());
        }
        if config.urls.is_empty()
            || config.urls.len() > config.max_sources
            || config.max_sources > 32
        {
            return Err("source count exceeds allowed range 1..32".into());
        }
        if config.chunk_bytes < 4096
            || config.chunk_bytes > 8_388_608
            || config.max_line_bytes == 0
            || config.max_line_bytes > 8192
            || config.max_line_bytes > config.chunk_bytes / 2
        {
            return Err("invalid chunk or line memory limits".into());
        }
        if config.max_run_files == 0
            || config.max_run_files > 128
            || config.max_input_bytes == 0
            || config.max_input_bytes > 268_435_456
            || config.max_output_bytes == 0
            || config.max_output_bytes > 268_435_456
        {
            return Err("invalid storage limits".into());
        }
        if config.download_timeout_secs == 0
            || config.download_timeout_secs > 60
            || config.build_timeout_secs == 0
            || config.build_timeout_secs > 60
        {
            return Err("timeouts must be within 1..60 seconds".into());
        }
        if !config.work_dir.is_absolute() {
            return Err("work_dir must be absolute".into());
        }
        if [&config.exclude_file, &config.state_dir]
            .into_iter()
            .flatten()
            .any(|path| !path.is_absolute())
        {
            return Err("exclude_file and state_dir must be absolute".into());
        }
        if let Some(api) = &config.adguard_api {
            // The observer sends a session cookie; never let it leave the host.
            let host = api.strip_prefix("http://").unwrap_or_default();
            if !host
                .parse::<SocketAddr>()
                .is_ok_and(|address| address.ip().is_loopback())
            {
                return Err("adguard_api must be http://LOOPBACK:PORT".into());
            }
        }
        if (config.adguard_api.is_some() || config.adaptive) && config.state_dir.is_none() {
            return Err("observation and adaptive mode require state_dir".into());
        }
        if config.observe_interval_secs == 0
            || config.state_flush_secs == 0
            || config.refresh_secs == 0
            || config.check_secs == 0
            || config.seen_max_entries == 0
            || config.seen_max_entries > 2_000_000
            || config.candidate_max_age_hours == 0
        {
            return Err("invalid observation limits".into());
        }
        Ok(config)
    }
}

struct Workspace(PathBuf);
impl Workspace {
    fn new(base: &Path) -> Result<Self> {
        fs::create_dir_all(base).map_err(|_| "cannot create work directory")?;
        for _ in 0..32 {
            let path = base.join(format!(
                "build-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("cannot create private staging directory".into()),
            }
        }
        Err("cannot allocate unique staging directory".into())
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn private_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "cannot create staging file".into())
}
struct Download(Child);
impl Drop for Download {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub rules: u64,
    /// Hash of the trimmed output; 0 when nothing was trimmed.
    pub fingerprint: u64,
}
struct Chunk {
    arena: Vec<u8>,
    offsets: Vec<(usize, usize)>,
    arena_limit: usize,
    entries_limit: usize,
}
impl Chunk {
    fn new(bytes: usize) -> Self {
        let arena_limit = bytes / 2;
        let entries_limit = (bytes - arena_limit) / std::mem::size_of::<(usize, usize)>();
        Self {
            arena: Vec::with_capacity(arena_limit),
            offsets: Vec::with_capacity(entries_limit),
            arena_limit,
            entries_limit,
        }
    }
    fn push(&mut self, line: &[u8]) -> bool {
        if self.arena.len() + line.len() > self.arena_limit
            || self.offsets.len() == self.entries_limit
        {
            return false;
        }
        self.offsets.push((self.arena.len(), line.len()));
        self.arena.extend_from_slice(line);
        true
    }
    fn flush(
        &mut self,
        workspace: &Workspace,
        runs: &mut Vec<PathBuf>,
        limit: usize,
    ) -> Result<()> {
        if self.offsets.is_empty() {
            return Ok(());
        }
        if runs.len() >= limit {
            return Err("sorted run count exceeds limit".into());
        }
        let arena = &self.arena;
        self.offsets
            .sort_unstable_by(|&(a, al), &(b, bl)| arena[a..a + al].cmp(&arena[b..b + bl]));
        let path = workspace.0.join(format!("run-{}", runs.len()));
        let mut writer = BufWriter::with_capacity(8192, private_file(&path)?);
        let mut previous: Option<(usize, usize)> = None;
        for &(start, len) in &self.offsets {
            let rule = &arena[start..start + len];
            if previous.is_some_and(|(p, n)| &arena[p..p + n] == rule) {
                continue;
            }
            writer
                .write_all(rule)
                .and_then(|_| writer.write_all(b"\n"))
                .map_err(|_| "cannot write sorted run")?;
            previous = Some((start, len));
        }
        writer.flush().map_err(|_| "cannot flush sorted run")?;
        runs.push(path);
        self.arena.clear();
        self.offsets.clear();
        Ok(())
    }
}
fn read_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>, limit: usize) -> Result<usize> {
    line.clear();
    loop {
        let buffer = reader.fill_buf().map_err(|_| "cannot read source")?;
        if buffer.is_empty() {
            return Ok(line.len());
        }
        let end = buffer
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buffer.len());
        if line.len() + end > limit + 2 {
            return Err("source line exceeds limit".into());
        }
        line.extend_from_slice(&buffer[..end]);
        reader.consume(end);
        if line.last() == Some(&b'\n') {
            return Ok(line.len());
        }
    }
}
fn rule(line: &[u8]) -> Result<Option<&[u8]>> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    // Preserve rule bytes; surrounding spaces may carry filter syntax meaning.
    let trimmed = line.trim_ascii();
    if trimmed.is_empty()
        || trimmed.starts_with(b"!")
        || trimmed.starts_with(b"#")
        || (line.starts_with(b"[Adblock Plus") && line.ends_with(b"]"))
    {
        return Ok(None);
    }
    if trimmed
        .get(..5)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"<html"))
        || trimmed
            .get(..14)
            .is_some_and(|v| v.eq_ignore_ascii_case(b"<!doctype html"))
    {
        return Err("source appears to be HTML".into());
    }
    if line.contains(&0) || std::str::from_utf8(line).is_err() {
        return Err("source contains invalid text".into());
    }
    Ok(Some(line))
}
fn deadline_check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err("build deadline exceeded".into())
    } else {
        Ok(())
    }
}
fn consume<R: BufRead>(
    reader: &mut R,
    config: &Config,
    workspace: &Workspace,
    chunk: &mut Chunk,
    runs: &mut Vec<PathBuf>,
    stats: &mut Stats,
    deadline: Instant,
) -> Result<u64> {
    let mut source_rules = 0;
    let mut line = Vec::with_capacity(config.max_line_bytes + 2);
    loop {
        deadline_check(deadline)?;
        let count = read_line(reader, &mut line, config.max_line_bytes)?;
        if count == 0 {
            break;
        }
        stats.input_bytes += count as u64;
        if stats.input_bytes > config.max_input_bytes {
            return Err("source input exceeds build limit".into());
        }
        if let Some(rule) = rule(&line)? {
            source_rules += 1;
            if rule.len() > config.max_line_bytes {
                return Err("source line exceeds limit".into());
            }
            if !chunk.push(rule) {
                chunk.flush(workspace, runs, config.max_run_files)?;
                if !chunk.push(rule) {
                    return Err("rule exceeds chunk capacity".into());
                }
            }
        }
    }
    Ok(source_rules)
}
fn combine(
    config: &Config,
    runs: &[PathBuf],
    output: &Path,
    stats: &mut Stats,
    deadline: Instant,
) -> Result<()> {
    let mut readers: Vec<_> = runs
        .iter()
        .map(|path| File::open(path).map(|file| BufReader::with_capacity(8192, file)))
        .collect::<io::Result<_>>()
        .map_err(|_| "cannot open sorted runs")?;
    let mut heap = BinaryHeap::with_capacity(runs.len());
    for (index, reader) in readers.iter_mut().enumerate() {
        let mut line = Vec::with_capacity(config.max_line_bytes + 2);
        if read_line(reader, &mut line, config.max_line_bytes)? > 0 {
            line.pop();
            heap.push(Reverse((line, index)));
        }
    }
    let mut writer = BufWriter::with_capacity(8192, private_file(output)?);
    let mut previous = Vec::with_capacity(config.max_line_bytes + 2);
    while let Some(Reverse((mut line, index))) = heap.pop() {
        deadline_check(deadline)?;
        if line != previous {
            stats.output_bytes += line.len() as u64 + 1;
            if stats.output_bytes > config.max_output_bytes {
                return Err("merged output exceeds limit".into());
            }
            writer
                .write_all(&line)
                .and_then(|_| writer.write_all(b"\n"))
                .map_err(|_| "cannot write merged list")?;
            previous.clear();
            previous.extend_from_slice(&line);
            stats.rules += 1;
        }
        if read_line(&mut readers[index], &mut line, config.max_line_bytes)? > 0 {
            line.pop();
            heap.push(Reverse((line, index)));
        }
    }
    writer.flush().map_err(|_| "cannot flush merged list")?;
    Ok(())
}
struct Build {
    workspace: Workspace,
    output: PathBuf,
    stats: Stats,
    _lock: File,
}
/// Take the build lock, clear abandoned staging and open a fresh workspace.
fn stage(config: &Config) -> Result<(File, Workspace)> {
    fs::create_dir_all(&config.work_dir).map_err(|_| "cannot create work directory")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(config.work_dir.join(".lock"))
        .map_err(|_| "cannot open build lock")?;
    lock.try_lock()
        .map_err(|_| "another build owns work directory")?;
    // Exclusive lock makes cleanup safe after crashes and interrupted deployments.
    for entry in fs::read_dir(&config.work_dir).map_err(|_| "cannot inspect staging")? {
        let entry = entry.map_err(|_| "cannot inspect staging entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str().and_then(|v| v.strip_prefix("build-")) else {
            continue;
        };
        let parts: Vec<_> = name.split('-').collect();
        if parts.len() == 2
            && parts
                .iter()
                .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            && entry
                .file_type()
                .map_err(|_| "cannot inspect staging type")?
                .is_dir()
        {
            fs::remove_dir_all(entry.path()).map_err(|_| "cannot clean abandoned staging")?;
        }
    }
    Ok((lock, Workspace::new(&config.work_dir)?))
}
fn build(config: &Config) -> Result<Build> {
    let (lock, workspace) = stage(config)?;
    let deadline = Instant::now() + Duration::from_secs(config.build_timeout_secs);
    let mut chunk = Chunk::new(config.chunk_bytes);
    let mut runs = Vec::new();
    let mut stats = Stats::default();
    for (index, url) in config.urls.iter().enumerate() {
        deadline_check(deadline)?;
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(1)
            .min(config.download_timeout_secs);
        let child = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--connect-timeout",
                "5",
                "--max-time",
                &remaining.to_string(),
                "--",
                url,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot launch curl")?;
        let mut download = Download(child);
        let mut reader = BufReader::with_capacity(
            8192,
            download.0.stdout.take().ok_or("cannot capture download")?,
        );
        let source_rules = consume(
            &mut reader,
            config,
            &workspace,
            &mut chunk,
            &mut runs,
            &mut stats,
            deadline,
        )
        .map_err(|error| format!("source {}: {error}", index + 1))?;
        if !download
            .0
            .wait()
            .map_err(|_| "cannot wait for download")?
            .success()
        {
            return Err(format!("source {} download failed", index + 1));
        }
        if source_rules == 0 {
            return Err(format!("source {} contains no rules", index + 1));
        }
    }
    chunk.flush(&workspace, &mut runs, config.max_run_files)?;
    drop(chunk);
    let output = workspace.0.join("filters.txt");
    combine(config, &runs, &output, &mut stats, deadline)?;
    if stats.rules == 0 {
        return Err("merged list contains no rules".into());
    }
    for path in runs {
        fs::remove_file(path).map_err(|_| "cannot remove sorted run")?;
    }
    Ok(Build {
        workspace,
        output,
        stats,
        _lock: lock,
    })
}
fn cached_candidate(config: &Config) -> Option<PathBuf> {
    let path = config.work_dir.join("candidate.txt");
    let age = fs::metadata(&path).ok()?.modified().ok()?;
    let limit = Duration::from_secs(config.candidate_max_age_hours * 3600);
    (SystemTime::now().duration_since(age).unwrap_or_default() < limit).then_some(path)
}
/// Merge the sources, then drop excluded rules and, when `observed` is given,
/// every domain rule that cannot match an observed name.
fn produce(config: &Config, observed: Option<&NameSet>) -> Result<Build> {
    let mut build = match (observed, cached_candidate(config)) {
        // Adaptive rebuilds are frequent; reuse the downloaded merge between them.
        (Some(_), Some(candidate)) => {
            let (lock, workspace) = stage(config)?;
            Build {
                workspace,
                output: candidate,
                stats: Stats::default(),
                _lock: lock,
            }
        }
        (Some(_), None) => {
            let candidate = config.work_dir.join("candidate.txt");
            match build(config) {
                Ok(mut build) => {
                    fs::rename(&build.output, &candidate)
                        .map_err(|_| "cannot cache merged candidates")?;
                    build.output = candidate;
                    build
                }
                Err(error) if candidate.exists() => {
                    eprintln!("filter-merge: reusing stale candidates: {error}");
                    let (lock, workspace) = stage(config)?;
                    Build {
                        workspace,
                        output: candidate,
                        stats: Stats::default(),
                        _lock: lock,
                    }
                }
                Err(error) => return Err(error),
            }
        }
        (None, _) => build(config)?,
    };
    let exclude = load_exclude(config)?;
    if exclude.is_none() && observed.is_none() {
        return Ok(build);
    }
    let trimmed = build.workspace.0.join("trimmed.txt");
    let mut reader = BufReader::with_capacity(
        8192,
        File::open(&build.output).map_err(|_| "cannot open merged candidates")?,
    );
    let mut writer = BufWriter::with_capacity(8192, private_file(&trimmed)?);
    let mut line = Vec::with_capacity(config.max_line_bytes + 2);
    build.stats.rules = 0;
    build.stats.output_bytes = 0;
    build.stats.fingerprint = FNV_OFFSET;
    while read_line(&mut reader, &mut line, config.max_line_bytes)? > 0 {
        let rule = line.strip_suffix(b"\n").unwrap_or(&line);
        if keeps(rule, exclude.as_ref(), observed) {
            build.stats.fingerprint = fnv(build.stats.fingerprint, &line);
            writer
                .write_all(&line)
                .map_err(|_| "cannot write trimmed list")?;
            build.stats.rules += 1;
            build.stats.output_bytes += line.len() as u64;
        }
    }
    writer.flush().map_err(|_| "cannot flush trimmed list")?;
    if build.stats.rules == 0 {
        // An empty answer would wipe the resolver's list; fail so it keeps the last one.
        return Err("trimmed list contains no rules".into());
    }
    build.output = trimmed;
    Ok(build)
}
fn keeps(rule: &[u8], exclude: Option<&NameSet>, observed: Option<&NameSet>) -> bool {
    adaptive::rule_domain(rule).is_none_or(|found| {
        !(found.plain && exclude.is_some_and(|set| set.contains(found.domain)))
            && observed.is_none_or(|set| set.contains(found.domain))
    })
}
fn load_exclude(config: &Config) -> Result<Option<NameSet>> {
    config
        .exclude_file
        .as_deref()
        .map(|path| NameSet::load(path, config.max_input_bytes))
        .transpose()
}
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
fn fnv(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}
/// Hash the list adaptive mode would serve now, without writing it.
/// `None` when no merged candidates are cached yet.
fn adaptive_fingerprint(config: &Config, observed: &NameSet) -> Result<Option<u64>> {
    let Ok(file) = File::open(config.work_dir.join("candidate.txt")) else {
        return Ok(None);
    };
    let exclude = load_exclude(config)?;
    let mut reader = BufReader::with_capacity(8192, file);
    let mut line = Vec::with_capacity(config.max_line_bytes + 2);
    let mut hash = FNV_OFFSET;
    while read_line(&mut reader, &mut line, config.max_line_bytes)? > 0 {
        let rule = line.strip_suffix(b"\n").unwrap_or(&line);
        if keeps(rule, exclude.as_ref(), Some(observed)) {
            hash = fnv(hash, &line);
        }
    }
    Ok(Some(hash))
}
/// Names whose rules adaptive mode serves today.
fn observed_names(config: &Config, seen: &Seen) -> NameSet {
    let oldest = match config.adaptive_max_age_days {
        0 => 0,
        days => adaptive::today().saturating_sub(days),
    };
    seen.suffixes(config.adaptive_min_queries, oldest)
}
fn seen_path(config: &Config) -> Option<PathBuf> {
    config.state_dir.as_ref().map(|dir| dir.join("seen.tsv"))
}
pub fn merge(config: &Config, output: &Path) -> Result<Stats> {
    let observed = match (config.adaptive, seen_path(config)) {
        (true, Some(path)) => Some(observed_names(config, &Seen::load(&path)?)),
        _ => None,
    };
    let build = produce(config, observed.as_ref())?;
    // Same-directory temporary output makes publication atomic across filesystems.
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let publication = Workspace::new(parent)?;
    let path = publication.0.join("filters.txt");
    let mut source = File::open(&build.output).map_err(|_| "cannot open merged list")?;
    let mut destination = private_file(&path)?;
    io::copy(&mut source, &mut destination).map_err(|_| "cannot copy merged list")?;
    destination
        .sync_all()
        .map_err(|_| "cannot sync merged list")?;
    fs::rename(path, output).map_err(|_| "cannot publish merged list")?;
    Ok(build.stats)
}

fn response(stream: &mut TcpStream, status: &str, body: &[u8], head: bool) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", body.len())?;
    if !head {
        stream.write_all(body)?;
    }
    Ok(())
}
fn request(stream: &mut TcpStream) -> Result<(String, bool)> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "socket timeout failed")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "socket timeout failed")?;
    let mut buffer = [0u8; 4096];
    let mut length = 0;
    loop {
        if length == buffer.len() {
            return Err("request headers too large".into());
        }
        let count = stream
            .read(&mut buffer[length..])
            .map_err(|_| "cannot read request")?;
        if count == 0 {
            return Err("incomplete request".into());
        }
        length += count;
        if buffer[..length].windows(4).any(|v| v == b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&buffer[..length]).map_err(|_| "invalid request")?;
    let mut parts = text
        .lines()
        .next()
        .ok_or("missing request line")?
        .split_whitespace();
    let method = parts.next().ok_or("missing method")?;
    let path = parts.next().ok_or("missing path")?;
    if method != "GET" && method != "HEAD" {
        return Err("method unsupported".into());
    }
    Ok((path.to_string(), method == "HEAD"))
}
fn send_build(stream: &mut TcpStream, result: &Result<Build>) {
    match result {
        Ok(build) => {
            let _keep_staging_alive = &build.workspace;
            let mut send = || -> io::Result<()> {
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n", build.stats.output_bytes)?;
                io::copy(&mut File::open(&build.output)?, stream)?;
                Ok(())
            };
            let _ = send();
        }
        Err(error) => {
            eprintln!("filter-merge: build failed: {error}");
            let _ = response(stream, "502 Bad Gateway", b"filter build failed\n", false);
        }
    }
}
#[derive(Default)]
struct State {
    seen: Seen,
    polls: u64,
    entries: u64,
    errors: u64,
    gaps: u64,
    refreshes: u64,
    last_error: String,
    /// Fingerprint of the adaptive list most recently served.
    served: Option<u64>,
}
type Shared = Arc<Mutex<State>>;
fn locked(shared: &Shared) -> std::sync::MutexGuard<'_, State> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
/// Poll the query log forever; flush the store and nudge AdGuard on a schedule.
fn observe(config: Config, shared: Shared, mut observer: Observer, store: PathBuf) {
    let mut last_flush = Instant::now();
    // Write a new store right after its first poll, not an hour later.
    let mut stored = store.exists();
    // None: no refresh requested yet, so the first change may go out at once.
    let mut last_refresh: Option<Instant> = None;
    let mut last_check = Instant::now();
    let mut checked_day = adaptive::today();
    loop {
        std::thread::sleep(Duration::from_secs(config.observe_interval_secs));
        let mut state = locked(&shared);
        state.polls += 1;
        match observer.poll(&mut state.seen) {
            Ok(poll) => {
                state.entries += poll.entries as u64;
                state.gaps += u64::from(poll.gap);
            }
            Err(error) => {
                state.errors += 1;
                state.last_error = error;
            }
        }
        if last_flush.elapsed().as_secs() >= config.state_flush_secs
            || (!stored && !state.seen.is_empty())
        {
            last_flush = Instant::now();
            stored = true;
            state.seen.prune(
                adaptive::today(),
                config.seen_max_age_days,
                config.seen_max_entries,
            );
            if state.seen.dirty {
                if let Err(error) = state.seen.save(&store) {
                    state.errors += 1;
                    state.last_error = error;
                }
            }
        }
        // New names can add rules; a new day can expire some. Only then, and only
        // once the refresh budget is open, work out whether the list would change.
        let day = adaptive::today();
        let due = config.adaptive
            && (state.seen.fresh || day != checked_day)
            && last_check.elapsed().as_secs() >= config.check_secs
            && last_refresh.is_none_or(|at| at.elapsed().as_secs() >= config.refresh_secs);
        if !due {
            continue;
        }
        last_check = Instant::now();
        checked_day = day;
        state.seen.fresh = false;
        let observed = observed_names(&config, &state.seen);
        let served = state.served;
        // AdGuard fetches from this process while refreshing; never hold the lock.
        drop(state);
        let result = match adaptive_fingerprint(&config, &observed) {
            Ok(fingerprint) if fingerprint.is_some() && fingerprint == served => continue,
            Ok(_) => {
                drop(observed);
                last_refresh = Some(Instant::now());
                locked(&shared).refreshes += 1;
                observer.refresh_filters()
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let mut state = locked(&shared);
            state.errors += 1;
            state.last_error = error;
        }
    }
}
fn cheap_request(stream: &mut TcpStream, path: &str, head: bool, shared: Option<&Shared>) -> bool {
    match path {
        "/stats" => {
            let body = match shared {
                Some(shared) => {
                    let state = locked(shared);
                    format!(
                        "observed_names={}\npolls={}\nentries={}\ngaps={}\nrefreshes={}\nerrors={}\nlast_error={}\n",
                        state.seen.len(),
                        state.polls,
                        state.entries,
                        state.gaps,
                        state.refreshes,
                        state.errors,
                        state.last_error
                    )
                }
                None => "observation disabled\n".to_string(),
            };
            let _ = response(stream, "200 OK", body.as_bytes(), head);
            true
        }
        "/healthz" | "/version" => {
            let _ = response(
                stream,
                "200 OK",
                format!("filter-merge {VERSION}\n").as_bytes(),
                head,
            );
            true
        }
        "/filters.txt" if head => {
            let _ = response(stream, "200 OK", b"", true);
            true
        }
        "/filters.txt" => false,
        _ => {
            let _ = response(stream, "404 Not Found", b"not found\n", head);
            true
        }
    }
}
pub fn serve(config: Config) -> Result<()> {
    let listener = TcpListener::bind(config.listen).map_err(|_| "cannot bind listener")?;
    let shared = match &config.state_dir {
        Some(directory) => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(|_| "cannot create state directory")?;
            let store = directory.join("seen.tsv");
            let shared: Shared = Arc::new(Mutex::new(State {
                seen: Seen::load(&store)?,
                ..State::default()
            }));
            if let Some(api) = &config.adguard_api {
                let observer = Observer::new(api, config.glinet_session, directory)?;
                let (config, shared) = (config.clone(), shared.clone());
                std::thread::spawn(move || observe(config, shared, observer, store));
            }
            Some(shared)
        }
        None => None,
    };
    eprintln!("filter-merge {VERSION}: listening on {}", config.listen);
    loop {
        listener
            .set_nonblocking(false)
            .map_err(|_| "cannot configure listener")?;
        let (mut stream, _) = listener.accept().map_err(|_| "cannot accept request")?;
        let (path, head) = match request(&mut stream) {
            Ok(value) => value,
            Err(_) => {
                let _ = response(&mut stream, "400 Bad Request", b"invalid request\n", false);
                continue;
            }
        };
        if cheap_request(&mut stream, &path, head, shared.as_ref()) {
            continue;
        }
        let observed = match (&shared, config.adaptive) {
            (Some(shared), true) => {
                let mut state = locked(shared);
                state.seen.fresh = false;
                Some(observed_names(&config, &state.seen))
            }
            _ => None,
        };
        let result = produce(&config, observed.as_ref());
        drop(observed);
        if let (Some(shared), true, Ok(build)) = (&shared, config.adaptive, &result) {
            locked(shared).served = Some(build.stats.fingerprint);
        }
        if let Ok(build) = &result {
            eprintln!(
                "filter-merge: input_bytes={} rules={} output_bytes={}",
                build.stats.input_bytes, build.stats.rules, build.stats.output_bytes
            );
        }
        send_build(&mut stream, &result);
        drop(stream);
        // Requests queued during the build consume this same completed generation.
        listener
            .set_nonblocking(true)
            .map_err(|_| "cannot configure listener")?;
        for _ in 0..32 {
            match listener.accept() {
                Ok((mut queued, _)) => match request(&mut queued) {
                    Ok((path, head)) => {
                        if !cheap_request(&mut queued, &path, head, shared.as_ref()) {
                            send_build(&mut queued, &result);
                        }
                    }
                    Err(_) => {
                        let _ =
                            response(&mut queued, "400 Bad Request", b"invalid request\n", false);
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("cannot accept queued request".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            chunk_bytes: 4096,
            max_line_bytes: 1024,
            ..Config::default()
        }
    }
    fn merge_text(text: &[u8], config: &Config) -> Result<(Vec<u8>, Stats)> {
        let workspace = Workspace::new(&std::env::temp_dir())?;
        let mut chunk = Chunk::new(config.chunk_bytes);
        let mut runs = Vec::new();
        let mut stats = Stats::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        consume(
            &mut io::Cursor::new(text),
            config,
            &workspace,
            &mut chunk,
            &mut runs,
            &mut stats,
            deadline,
        )?;
        chunk.flush(&workspace, &mut runs, config.max_run_files)?;
        let output = workspace.0.join("output");
        combine(config, &runs, &output, &mut stats, deadline)?;
        Ok((fs::read(output).unwrap(), stats))
    }
    #[test]
    fn preserves_rule_semantics_and_removes_only_exact_duplicates() {
        let input = b"! comment\r\n# comment\n[Adblock Plus 2.0]\n||example.com^\n@@||example.com^$important\n0.0.0.0 example.com\nexample.com\n||example.com^\r\n";
        let (output, stats) = merge_text(input, &config()).unwrap();
        assert_eq!(
            output,
            b"0.0.0.0 example.com\n@@||example.com^$important\nexample.com\n||example.com^\n"
        );
        assert_eq!(stats.rules, 4);
    }
    #[test]
    fn deduplicates_across_many_chunks() {
        let input: String = (0..1000)
            .rev()
            .chain(0..1000)
            .map(|n| format!("domain{n:04}.example\n"))
            .collect();
        let (output, stats) = merge_text(input.as_bytes(), &config()).unwrap();
        let expected: String = (0..1000)
            .map(|n| format!("domain{n:04}.example\n"))
            .collect();
        assert_eq!(output, expected.as_bytes());
        assert_eq!(stats.rules, 1000);
    }
    #[test]
    fn rejects_limits() {
        let mut config = config();
        config.max_line_bytes = 3;
        assert!(merge_text(b"abcd\n", &config).is_err());
        config.max_line_bytes = 1024;
        config.max_input_bytes = 3;
        assert!(merge_text(b"abcd\n", &config).is_err());
        config.max_input_bytes = 100;
        config.max_output_bytes = 3;
        assert!(merge_text(b"abcd\n", &config).is_err());
        config.max_input_bytes = 100000;
        config.max_output_bytes = 100000;
        config.max_run_files = 1;
        let many_rules: String = (0..300)
            .map(|n| format!("domain{n:04}.example\n"))
            .collect();
        assert!(merge_text(many_rules.as_bytes(), &config)
            .unwrap_err()
            .contains("run count"));
    }
    #[test]
    fn rejects_html_and_ignores_whitespace_only_lines() {
        assert!(merge_text(b"<!DOCTYPE html>\n", &config()).is_err());
        assert!(merge_text(b"  <HTML>\n", &config()).is_err());
        let (output, _) =
            merge_text(b" \t\n  ! comment\n  # comment\na\na\t\na \n", &config()).unwrap();
        assert_eq!(output, b"a\na\t\na \n");
    }
    #[test]
    fn staging_removed_after_failed_download() {
        let base = Workspace::new(&std::env::temp_dir()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request);
            socket
                .write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let config = Config {
            work_dir: base.0.clone(),
            urls: vec![format!("http://{address}/filters")],
            ..Config::default()
        };
        assert!(build(&config).is_err());
        thread.join().unwrap();
        let remaining: Vec<_> = fs::read_dir(&base.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(remaining, vec![std::ffi::OsString::from(".lock")]);
    }
    #[test]
    fn config_restricts_exposure_and_protocols() {
        assert!(Config::parse("listen=0.0.0.0:3054\nurl=https://example.com/list").is_err());
        assert!(Config::parse("url=file:///etc/passwd").is_err());
        assert!(Config::parse("url=https://example.com/list").is_ok());
    }
}
