//! Observed-domain store and rule trimming for adaptive lists.
//!
//! A resolver only needs block rules for names its clients actually ask for.
//! The observer records every queried name from AdGuard Home's query log; the
//! filter then keeps a candidate rule only when it could match a recorded name.

use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, String>;

const GLINET_TOKEN_PREFIX: &str = "/tmp/gl_token_";
const PAGE_ENTRIES: usize = 200;
const MAX_PAGES: usize = 5;
/// An empty store reads the whole available log once: 50,000 entries at most.
const BOOTSTRAP_PAGES: usize = 250;
const MAX_PAGE_BYTES: u64 = 4 * 1024 * 1024;

pub fn today() -> u32 {
    (unix_seconds() / 86_400) as u32
}
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}
fn is_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.contains(&b'.')
        && value.iter().all(|&byte| name_byte(byte))
        && !value.starts_with(b".")
        && !value.ends_with(b".")
}

/// Domain a rule is keyed on, when the rule has one of the plain domain forms.
#[derive(Debug, PartialEq)]
pub struct RuleDomain<'a> {
    pub domain: &'a [u8],
    /// No exception marker and no modifiers: safe to drop by domain alone.
    pub plain: bool,
}

/// Extract the domain of `||d^`, `||d^$mods`, hosts and bare-domain rules.
/// Anything else (regexes, wildcards, paths) returns `None` and is always kept.
pub fn rule_domain(rule: &[u8]) -> Option<RuleDomain<'_>> {
    let rule = rule.trim_ascii();
    let (body, exception) = match rule.strip_prefix(b"@@") {
        Some(rest) => (rest, true),
        None => (rule, false),
    };
    if let Some(rest) = body.strip_prefix(b"||") {
        let end = rest
            .iter()
            .position(|&byte| !name_byte(byte))
            .unwrap_or(rest.len());
        let (domain, tail) = rest.split_at(end);
        let modifiers = match tail {
            b"" | b"^" => false,
            _ if tail.starts_with(b"^$") || tail.starts_with(b"$") => true,
            _ => return None,
        };
        return is_name(domain).then_some(RuleDomain {
            domain,
            plain: !exception && !modifiers,
        });
    }
    if exception {
        return None;
    }
    let mut fields = body
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|f| !f.is_empty());
    let first = fields.next()?;
    let domain = match (fields.next(), fields.next()) {
        (None, _) => first,
        (Some(host), None) if matches!(first, b"0.0.0.0" | b"127.0.0.1" | b"::" | b"::1") => host,
        _ => return None,
    };
    is_name(domain).then_some(RuleDomain {
        domain,
        plain: true,
    })
}

/// Sorted, deduplicated byte strings with binary-search lookup; far smaller
/// than a hash set for a few hundred thousand names.
#[derive(Default)]
pub struct NameSet {
    arena: Vec<u8>,
    spans: Vec<(u32, u32)>,
}
impl NameSet {
    pub fn push(&mut self, name: &[u8]) {
        self.spans
            .push((self.arena.len() as u32, name.len() as u32));
        self.arena.extend(name.iter().map(u8::to_ascii_lowercase));
    }
    fn get(&self, index: usize) -> &[u8] {
        let (start, len) = self.spans[index];
        &self.arena[start as usize..(start + len) as usize]
    }
    pub fn finish(mut self) -> Self {
        let arena = std::mem::take(&mut self.arena);
        let slice = |&(start, len): &(u32, u32)| &arena[start as usize..(start + len) as usize];
        self.spans.sort_unstable_by(|a, b| slice(a).cmp(slice(b)));
        self.spans.dedup_by(|a, b| slice(a) == slice(b));
        self.arena = arena;
        self
    }
    pub fn len(&self) -> usize {
        self.spans.len()
    }
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
    /// Case-insensitive membership; the set itself is stored lowercase.
    pub fn contains(&self, name: &[u8]) -> bool {
        let (mut low, mut high) = (0, self.spans.len());
        while low < high {
            let middle = (low + high) / 2;
            let order = self
                .get(middle)
                .iter()
                .copied()
                .cmp(name.iter().map(u8::to_ascii_lowercase));
            match order {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }
    /// One domain per line; blank lines and `#` comments are skipped.
    pub fn load(path: &Path, limit: u64) -> Result<Self> {
        let mut text = Vec::new();
        File::open(path)
            .map_err(|_| "cannot read exclude file")?
            .take(limit + 1)
            .read_to_end(&mut text)
            .map_err(|_| "cannot read exclude file")?;
        if text.len() as u64 > limit {
            return Err("exclude file exceeds input limit".into());
        }
        let mut set = Self::default();
        for line in text.split(|&byte| byte == b'\n') {
            let line = line.trim_ascii();
            if !line.is_empty() && !line.starts_with(b"#") {
                set.push(line);
            }
        }
        Ok(set.finish())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Record {
    pub first_day: u32,
    pub last_day: u32,
    pub queries: u64,
    pub blocked: u64,
}

/// Every name clients asked for, with day-resolution first/last sighting.
#[derive(Default)]
pub struct Seen {
    map: HashMap<String, Record>,
    /// Counts changed since the last save.
    pub dirty: bool,
    /// Names were added since the last list build.
    pub fresh: bool,
}
impl Seen {
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn get(&self, name: &str) -> Option<&Record> {
        self.map.get(name)
    }
    /// Record one sighting. Local-only and malformed names are ignored.
    pub fn note(&mut self, name: &str, day: u32, blocked: bool) {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if !is_name(name.as_bytes())
            || [".arpa", ".local", ".lan", ".internal"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            return;
        }
        self.dirty = true;
        let record = self.map.entry(name).or_insert_with(|| {
            self.fresh = true;
            Record {
                first_day: day,
                last_day: day,
                queries: 0,
                blocked: 0,
            }
        });
        record.last_day = record.last_day.max(day);
        record.queries += 1;
        record.blocked += u64::from(blocked);
    }
    /// Drop expired names, then the least recently seen beyond `max_entries`.
    pub fn prune(&mut self, day: u32, max_age_days: u32, max_entries: usize) {
        let before = self.map.len();
        if max_age_days > 0 {
            self.map
                .retain(|_, record| day.saturating_sub(record.last_day) <= max_age_days);
        }
        if self.map.len() > max_entries {
            let mut days: Vec<u32> = self.map.values().map(|record| record.last_day).collect();
            days.sort_unstable();
            let excess = self.map.len() - max_entries;
            let cutoff = days[excess];
            // everything older than the cutoff day goes, plus enough of that day
            let mut at_cutoff = excess - days.partition_point(|&day| day < cutoff);
            self.map.retain(|_, record| {
                if record.last_day == cutoff && at_cutoff > 0 {
                    at_cutoff -= 1;
                    return false;
                }
                record.last_day >= cutoff
            });
        }
        self.dirty |= self.map.len() != before;
    }
    /// Every name with enough queries, last seen on or after `oldest_day`,
    /// plus all of its parent domains.
    pub fn suffixes(&self, min_queries: u64, oldest_day: u32) -> NameSet {
        let mut set = NameSet::default();
        for (name, record) in &self.map {
            if record.queries < min_queries || record.last_day < oldest_day {
                continue;
            }
            let mut rest = name.as_str();
            loop {
                set.push(rest.as_bytes());
                match rest.split_once('.') {
                    Some((_, parent)) => rest = parent,
                    None => break,
                }
            }
        }
        set.finish()
    }
    pub fn load(path: &Path) -> Result<Self> {
        let mut seen = Self::default();
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(seen),
            Err(_) => return Err("cannot read observed-domain store".into()),
        };
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|_| "cannot read observed-domain store")?;
            let mut fields = line.split('\t');
            let name = fields.next().unwrap_or_default();
            let mut number = || fields.next().and_then(|value| value.parse::<u64>().ok());
            let (Some(first), Some(last), Some(queries), Some(blocked)) =
                (number(), number(), number(), number())
            else {
                return Err("observed-domain store is corrupt".into());
            };
            seen.map.insert(
                name.to_string(),
                Record {
                    first_day: first as u32,
                    last_day: last as u32,
                    queries,
                    blocked,
                },
            );
        }
        Ok(seen)
    }
    /// Atomic replace; one sorted line per name so the file diffs and greps well.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        let temporary = path.with_extension("tmp");
        let _ = fs::remove_file(&temporary);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "cannot write observed-domain store")?;
        let mut names: Vec<&String> = self.map.keys().collect();
        names.sort_unstable();
        let mut writer = BufWriter::new(file);
        for name in names {
            let record = &self.map[name];
            writeln!(
                writer,
                "{name}\t{}\t{}\t{}\t{}",
                record.first_day, record.last_day, record.queries, record.blocked
            )
            .map_err(|_| "cannot write observed-domain store")?;
        }
        let file = writer
            .into_inner()
            .map_err(|_| "cannot write observed-domain store")?;
        file.sync_all()
            .map_err(|_| "cannot sync observed-domain store")?;
        fs::rename(&temporary, path).map_err(|_| "cannot publish observed-domain store")?;
        self.dirty = false;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub time: String,
    pub name: String,
    pub blocked: bool,
    /// CNAME targets in the answer; rules often match these, not the question.
    pub cnames: Vec<String>,
}
#[derive(Debug, PartialEq)]
pub struct Page {
    pub entries: Vec<Entry>,
    pub oldest: String,
}

/// Parse one `/control/querylog` response, newest entry first.
pub fn parse_querylog(body: &[u8]) -> Result<Page> {
    let root: Value = serde_json::from_slice(body).map_err(|_| "query log is not JSON")?;
    let data = root
        .get("data")
        .and_then(Value::as_array)
        .ok_or("query log has no data array")?;
    let text = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut entries = Vec::with_capacity(data.len());
    for item in data {
        let Some(question) = item.get("question") else {
            continue;
        };
        let mut cnames = Vec::new();
        for key in ["answer", "original_answer"] {
            for answer in item
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if answer.get("type").and_then(Value::as_str) == Some("CNAME") {
                    cnames.push(text(answer, "value"));
                }
            }
        }
        entries.push(Entry {
            time: text(item, "time"),
            name: text(question, "name"),
            blocked: text(item, "reason").starts_with("Filtered"),
            cnames,
        });
    }
    Ok(Page {
        entries,
        oldest: text(&root, "oldest"),
    })
}

#[derive(Debug, Default, PartialEq)]
pub struct Poll {
    pub entries: usize,
    /// The log wrapped past the previous watermark; some queries went unseen.
    pub gap: bool,
}

/// Incremental reader of AdGuard Home's in-memory query log.
pub struct Observer {
    api: String,
    glinet_token: Option<String>,
    watermark: Option<String>,
}
impl Observer {
    pub fn new(api: &str, glinet_session: bool, state_dir: &Path) -> Result<Self> {
        let glinet_token = glinet_session
            .then(|| glinet_token(&state_dir.join("gl-token")))
            .transpose()?;
        Ok(Self {
            api: api.trim_end_matches('/').to_string(),
            glinet_token,
            watermark: None,
        })
    }
    /// curl config on stdin keeps the session token out of the process list.
    fn curl(&self, url: &str, post: Option<&str>, seconds: u32) -> Result<Vec<u8>> {
        let mut config = format!("url = \"{url}\"\n");
        if let Some(token) = &self.glinet_token {
            // GL.iNet builds accept a session whose token file is younger than their timeout.
            write_private(
                &PathBuf::from(format!("{GLINET_TOKEN_PREFIX}{token}")),
                &(unix_seconds() as u32).to_ne_bytes(),
            )?;
            config.push_str(&format!("header = \"Cookie: Admin-Token={token}\"\n"));
        }
        if let Some(body) = post {
            config.push_str("header = \"Content-Type: application/json\"\n");
            config.push_str(&format!("data = \"{}\"\n", body.replace('"', "\\\"")));
        }
        let mut child = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--max-time",
                &seconds.to_string(),
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot launch curl")?;
        child
            .stdin
            .take()
            .ok_or("cannot reach curl")?
            .write_all(config.as_bytes())
            .map_err(|_| "cannot configure curl")?;
        let mut body = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or("cannot capture curl")?
            .take(MAX_PAGE_BYTES + 1)
            .read_to_end(&mut body);
        if read.is_err() || body.len() as u64 > MAX_PAGE_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err("AdGuard response too large or unreadable".into());
        }
        if !child.wait().map_err(|_| "cannot wait for curl")?.success() {
            return Err("AdGuard request failed".into());
        }
        Ok(body)
    }
    /// Record entries newer than the last poll's newest entry.
    pub fn poll(&mut self, seen: &mut Seen) -> Result<Poll> {
        let day = today();
        let mut poll = Poll::default();
        let mut newest = None;
        let mut older_than = String::new();
        let mut reached = false;
        // Seed a new store from all the history AdGuard still has. Later polls
        // stay shallow, so a restart recounts little.
        let pages = if seen.is_empty() && self.watermark.is_none() {
            BOOTSTRAP_PAGES
        } else {
            MAX_PAGES
        };
        'pages: for _ in 0..pages {
            let mut url = format!("{}/control/querylog?limit={PAGE_ENTRIES}", self.api);
            if !older_than.is_empty() {
                url.push_str(&format!("&older_than={}", older_than.replace('+', "%2B")));
            }
            let page = parse_querylog(&self.curl(&url, None, 10)?)?;
            for entry in &page.entries {
                if self.watermark.as_deref() == Some(entry.time.as_str()) {
                    reached = true;
                    break 'pages;
                }
                newest.get_or_insert_with(|| entry.time.clone());
                seen.note(&entry.name, day, entry.blocked);
                for cname in &entry.cnames {
                    seen.note(cname, day, false);
                }
                poll.entries += 1;
            }
            if page.entries.len() < PAGE_ENTRIES || page.oldest.is_empty() {
                reached = true;
                break;
            }
            older_than = page.oldest;
        }
        poll.gap = self.watermark.is_some() && !reached;
        if newest.is_some() {
            self.watermark = newest;
        }
        Ok(poll)
    }
    /// Ask AdGuard Home to re-fetch its subscriptions now.
    pub fn refresh_filters(&self) -> Result<()> {
        let url = format!("{}/control/filtering/refresh", self.api);
        self.curl(&url, Some("{\"whitelist\":false}"), 120)
            .map(|_| ())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|_| "cannot write session token".into())
}

/// Reuse one random token name across restarts so stale sessions never pile up.
fn glinet_token(path: &Path) -> Result<String> {
    if let Ok(token) = fs::read_to_string(path) {
        if token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(token);
        }
    }
    let mut random = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| "cannot read random bytes")?;
    let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    write_private(path, token.as_bytes())?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(rule: &str) -> Option<(&str, bool)> {
        rule_domain(rule.as_bytes())
            .map(|found| (std::str::from_utf8(found.domain).unwrap(), found.plain))
    }
    #[test]
    fn extracts_domains_only_from_plain_forms() {
        assert_eq!(
            domain("||ads.example.com^"),
            Some(("ads.example.com", true))
        );
        assert_eq!(
            domain("||ads.example.com^$important"),
            Some(("ads.example.com", false))
        );
        assert_eq!(
            domain("@@||ok.example.com^"),
            Some(("ok.example.com", false))
        );
        assert_eq!(
            domain("0.0.0.0 ads.example.com"),
            Some(("ads.example.com", true))
        );
        assert_eq!(domain("ads.example.com"), Some(("ads.example.com", true)));
        for kept in [
            "||ads*.example.com^",
            "/^ads[0-9]+\\./",
            "||example.com/path",
            "0.0.0.0 a.example b.example",
            "10.0.0.1 router.example",
            "@@ok.example.com",
            "localhost",
        ] {
            assert_eq!(domain(kept), None, "{kept}");
        }
    }
    #[test]
    fn name_set_matches_case_insensitively() {
        let mut set = NameSet::default();
        for name in ["b.example", "A.example", "b.example"] {
            set.push(name.as_bytes());
        }
        let set = set.finish();
        assert_eq!(set.len(), 2);
        assert!(set.contains(b"a.example") && set.contains(b"B.EXAMPLE"));
        assert!(!set.contains(b"c.example") && !set.contains(b"a.exampl"));
    }
    #[test]
    fn seen_counts_and_covers_parent_domains() {
        let mut seen = Seen::default();
        seen.note("Sub.Ads.Example.com.", 10, true);
        seen.note("sub.ads.example.com", 12, false);
        seen.note("printer.lan", 12, false);
        seen.note("1.0.168.192.in-addr.arpa", 12, false);
        seen.note("not a name", 12, false);
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen.get("sub.ads.example.com"),
            Some(&Record {
                first_day: 10,
                last_day: 12,
                queries: 2,
                blocked: 1
            })
        );
        let suffixes = seen.suffixes(1, 12);
        for name in [
            "sub.ads.example.com",
            "ads.example.com",
            "example.com",
            "com",
        ] {
            assert!(suffixes.contains(name.as_bytes()), "{name}");
        }
        assert!(!suffixes.contains(b"other.example.com"));
        assert!(seen.suffixes(3, 0).is_empty());
        // last seen on day 12, so a window starting on day 13 no longer serves it
        assert!(seen.suffixes(1, 13).is_empty());
    }
    #[test]
    fn seen_round_trips_and_prunes() {
        let directory = std::env::temp_dir().join(format!("fm-seen-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("seen.tsv");
        let mut seen = Seen::default();
        for (name, day) in [
            ("old.example", 1),
            ("mid.example", 50),
            ("new.example", 100),
        ] {
            seen.note(name, day, false);
        }
        seen.save(&path).unwrap();
        assert!(!seen.dirty);
        let mut loaded = Seen::load(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded.get("mid.example"), seen.get("mid.example"));
        loaded.prune(100, 60, 10);
        assert!(loaded.get("old.example").is_none() && loaded.len() == 2);
        loaded.prune(100, 0, 1);
        assert!(loaded.get("new.example").is_some() && loaded.len() == 1);
        fs::write(&path, "broken line\n").unwrap();
        assert!(Seen::load(&path).is_err());
        assert!(Seen::load(&directory.join("missing")).unwrap().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn parses_query_log_with_cnames_and_block_reasons() {
        let body = br#"{"data":[
          {"question":{"name":"site.example","type":"A"},"reason":"NotFilteredNotFound",
           "time":"2026-01-02T03:04:05.000000006Z",
           "answer":[{"type":"CNAME","value":"edge.tracker.example."},{"type":"A","value":"1.2.3.4"}]},
          {"question":{"name":"ads.example","type":"HTTPS"},"reason":"FilteredBlackList",
           "time":"2026-01-02T03:04:04Z","answer":[{"type":"HTTPS","value":"alpn=\"h3,h2\""}],
           "original_answer":[{"type":"CNAME","value":"x.cdn.example"}]}
        ],"oldest":"2026-01-02T03:04:04Z"}"#;
        let page = parse_querylog(body).unwrap();
        assert_eq!(page.oldest, "2026-01-02T03:04:04Z");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].cnames, ["edge.tracker.example."]);
        assert!(!page.entries[0].blocked && page.entries[1].blocked);
        assert_eq!(page.entries[1].cnames, ["x.cdn.example"]);
        assert!(parse_querylog(b"<html>").is_err());
        assert!(parse_querylog(b"{}").is_err());
    }
}
