use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
fn build(config: &Config) -> Result<Build> {
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
    let workspace = Workspace::new(&config.work_dir)?;
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
pub fn merge(config: &Config, output: &Path) -> Result<Stats> {
    let build = build(config)?;
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
fn cheap_request(stream: &mut TcpStream, path: &str, head: bool) -> bool {
    match path {
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
        if cheap_request(&mut stream, &path, head) {
            continue;
        }
        let result = build(&config);
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
                        if !cheap_request(&mut queued, &path, head) {
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
