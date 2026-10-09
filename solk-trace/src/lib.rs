//! Opt-in lab instrumentation. No consensus data or transaction bytes are changed.
//! Producers never wait for disk, HTTP, or the collector. CLI registration/flush
//! are deliberately separate from the validator hot path.
use base64::{engine::general_purpose::STANDARD, Engine};
pub use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct Selection {
    run: String,
    trace: String,
}
#[derive(Clone)]
struct Context {
    signature: String,
    slot: u64,
    bank: String,
    mode: String,
    attempt: String,
}
thread_local! { static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) }; static MODE: RefCell<String> = RefCell::new("unknown".into()); static BANK: RefCell<String> = RefCell::new("unknown".into()); }
enum Item {
    Event(Value, Option<(String, Vec<u8>)>, u64),
    Flush(mpsc::Sender<()>),
}
struct Recorder {
    root: PathBuf,
    boot: String,
    node: String,
    start: Instant,
    sender: SyncSender<Item>,
    queued_bytes: AtomicU64,
    seq: AtomicU64,
    dropped: AtomicU64,
    queue_full: AtomicU64,
    byte_budget_exceeded: AtomicU64,
    io_errors: AtomicU64,
    attempts: AtomicU64,
    selections: Arc<Mutex<HashMap<String, Selection>>>,
    control: Arc<Mutex<Value>>,
}
static RECORDER: OnceLock<Option<Recorder>> = OnceLock::new();
// Replay after an interruption produces bursts far above the steady-state
// packet rate. Independent item and byte bounds avoid exhausting the item
// queue while most of the memory budget remains unused.
const QUEUE_ITEMS: usize = 65_536;
const QUEUE_BYTES: u64 = 128 * 1024 * 1024;
fn now_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}
fn recorder() -> Option<&'static Recorder> {
    RECORDER
        .get_or_init(|| {
            let directory = std::env::var_os("SOLK_TRACE_DIR")?;
            if directory.is_empty() {
                return None;
            }
            let root = PathBuf::from(directory);
            let node = std::env::var("NODE").unwrap_or_else(|_| "client".into());
            let boot = format!("{}-{}", now_us(), std::process::id());
            let dir = root.join("events").join(format!("{node}-{boot}"));
            fs::create_dir_all(&dir).ok()?;
            fs::create_dir_all(root.join("payloads")).ok()?;
            let (sender, receiver) = mpsc::sync_channel(QUEUE_ITEMS);
            let writer_root = root.clone();
            let health = dir.join("health.json");
            let selections = Arc::new(Mutex::new(HashMap::new()));
            let control = Arc::new(Mutex::new(Value::Null));
            refresh(&root, &selections, &control);
            let writer_selections = selections.clone();
            let writer_control = control.clone();
            thread::Builder::new()
                .name("solkTraceWriter".into())
                .spawn(move || {
                    let mut writer = Writer::new(writer_root, dir, health);
                    let mut last_refresh = Instant::now();
                    let mut last_health = Instant::now();
                    loop {
                        match receiver.recv_timeout(Duration::from_millis(50)) {
                            Ok(Item::Event(event, payload, charge)) => {
                                writer.accept(event, payload, charge)
                            }
                            Ok(Item::Flush(done)) => {
                                writer.flush();
                                writer.health();
                                let _ = done.send(());
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => writer.flush(),
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                        if last_refresh.elapsed() > Duration::from_millis(100) {
                            refresh(&writer.root, &writer_selections, &writer_control);
                            writer.refresh_fecs();
                            writer.drain_pending();
                            last_refresh = Instant::now();
                        }
                        if last_health.elapsed() > Duration::from_secs(1) {
                            writer.flush();
                            writer.health();
                            last_health = Instant::now();
                        }
                    }
                })
                .ok()?;
            Some(Recorder {
                root,
                boot,
                node,
                start: Instant::now(),
                sender,
                queued_bytes: AtomicU64::new(0),
                seq: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                queue_full: AtomicU64::new(0),
                byte_budget_exceeded: AtomicU64::new(0),
                io_errors: AtomicU64::new(0),
                attempts: AtomicU64::new(0),
                selections,
                control,
            })
        })
        .as_ref()
}

type Payload = Option<(String, Vec<u8>)>;
struct Writer {
    root: PathBuf,
    dir: PathBuf,
    health_path: PathBuf,
    out: Option<BufWriter<File>>,
    chunk: u64,
    size: usize,
    errors: u64,
    written: u64,
    removed: u64,
    filtered: u64,
    fecs: HashMap<(u64, u64), HashSet<String>>,
    fec_files: HashSet<PathBuf>,
    pending: VecDeque<(Instant, Value, Payload, u64)>,
}
impl Writer {
    fn new(root: PathBuf, dir: PathBuf, health_path: PathBuf) -> Self {
        let _ = fs::create_dir_all(root.join("fecs"));
        let out = File::create(dir.join("events-000000.ndjson"))
            .map(BufWriter::new)
            .ok();
        Self {
            root,
            dir,
            health_path,
            out,
            chunk: 0,
            size: 0,
            errors: 0,
            written: 0,
            removed: 0,
            filtered: 0,
            fecs: HashMap::new(),
            fec_files: HashSet::new(),
            pending: VecDeque::new(),
        }
    }
    fn release(charge: u64) {
        if let Some(r) = RECORDER.get().and_then(Option::as_ref) {
            r.queued_bytes.fetch_sub(charge, Ordering::Relaxed);
        }
    }
    fn shred_event(event: &Value) -> bool {
        let name = event["event"].as_str().unwrap_or("");
        name.starts_with("broadcast.shred.")
            || name.starts_with("tvu.shred.")
            || name.starts_with("blockstore.shred.")
    }
    fn selected_fec(&self, event: &Value) -> bool {
        let (Some(slot), Some(fec)) = (
            event["slot"].as_u64(),
            event["data"]["fec_set_index"].as_u64(),
        ) else {
            return false;
        };
        self.fecs.get(&(slot, fec)).is_some_and(|roots| {
            event["data"]["merkle_root"].as_str().is_some_and(|actual| roots.contains(actual))
        })
    }

    fn accept(&mut self, event: Value, payload: Payload, charge: u64) {
        if event["event"] == "broadcast.entry_batch" {
            let slot = event["slot"].as_u64().unwrap_or(0);
            if let Some(shreds) = event["data"]["shreds"].as_array() {
                for shred in shreds {
                    let (Some(fec), Some(root)) = (
                        shred["fec_set_index"].as_u64(),
                        shred["merkle_root"].as_str(),
                    ) else {
                        continue;
                    };
                    if !self.fecs.entry((slot, fec)).or_default().insert(root.into()) {
                        continue;
                    }
                    // One immutable file per Merkle root; forks cannot overwrite each other.
                    let path = self.root.join("fecs").join(format!("{slot}-{fec}-{root}.json"));
                    self.fec_files.insert(path.clone());
                    let temp = path.with_extension(format!(
                        "{}-tmp",
                        event["process_boot_id"].as_str().unwrap_or("writer")
                    ));
                    let value = json!({"slot":slot,"fec_set_index":fec,"merkle_root":root,"run_id":event["run_id"]});
                    if fs::write(&temp, value.to_string())
                        .and_then(|_| fs::rename(temp, path))
                        .is_err()
                    {
                        self.errors += 1;
                    }
                }
            }
        }
        if Self::shred_event(&event) && !self.selected_fec(&event) {
            self.pending
                .push_back((Instant::now(), event, payload, charge));
        } else {
            self.write_event(event, payload);
            Self::release(charge);
        }
    }
    fn refresh_fecs(&mut self) {
        if let Ok(entries) = fs::read_dir(self.root.join("fecs")) {
            for entry in entries.flatten().take(4096) {
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                if self.fec_files.contains(&path) { continue; }
                if let Ok(raw) = fs::read(&path) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
                        if let (Some(slot), Some(fec), Some(root)) = (
                            v["slot"].as_u64(),
                            v["fec_set_index"].as_u64(),
                            v["merkle_root"].as_str(),
                        ) {
                            self.fecs.entry((slot, fec)).or_default().insert(root.into());
                            self.fec_files.insert(path);
                        }
                    }
                }
            }
        }
    }
    fn drain_pending(&mut self) {
        let count = self.pending.len();
        for _ in 0..count {
            let Some((time, event, payload, charge)) = self.pending.pop_front() else {
                break;
            };
            if self.selected_fec(&event) {
                self.write_event(event, payload);
                Self::release(charge);
            } else if time.elapsed() > Duration::from_secs(2) {
                self.filtered += 1;
                Self::release(charge);
            } else {
                self.pending.push_back((time, event, payload, charge));
            }
        }
    }
    fn write_event(&mut self, event: Value, payload: Payload) {
        if let Some((hash, bytes)) = payload {
            let path = self.root.join("payloads").join(format!("{hash}.bin"));
            if !path.exists() {
                // Containers often have the same PID. Boot and node make this temporary path unique.
                let temp = path.with_extension(format!(
                    "{}-{}-tmp",
                    event["node_id"].as_str().unwrap_or("writer"),
                    event["process_boot_id"].as_str().unwrap_or("boot")
                ));
                if fs::write(&temp, bytes)
                    .and_then(|_| fs::rename(&temp, &path))
                    .is_err()
                {
                    self.errors += 1;
                }
            }
        }
        if let Ok(mut line) = serde_json::to_vec(&event) {
            line.push(b'\n');
            if self
                .out
                .as_mut()
                .is_some_and(|out| out.write_all(&line).is_ok())
            {
                self.written += 1;
                self.size += line.len();
            } else {
                self.errors += 1;
            }
        }
        if self.size >= 8 * 1024 * 1024 {
            self.flush();
            self.chunk += 1;
            self.size = 0;
            self.out = File::create(self.dir.join(format!("events-{:06}.ndjson", self.chunk)))
                .map(BufWriter::new)
                .ok();
            if self.chunk >= 16
                && fs::remove_file(
                    self.dir
                        .join(format!("events-{:06}.ndjson", self.chunk - 16)),
                )
                .is_ok()
            {
                self.removed += 1;
            }
        }
    }
    fn flush(&mut self) {
        if let Some(out) = self.out.as_mut() {
            if out.flush().is_err() {
                self.errors += 1;
            }
        }
    }
    fn health(&mut self) {
        let (seq, dropped, producer_errors, queued) = RECORDER
            .get()
            .and_then(Option::as_ref)
            .map(|r| {
                (
                    r.seq.load(Ordering::Relaxed),
                    r.dropped.load(Ordering::Relaxed),
                    r.io_errors.load(Ordering::Relaxed),
                    r.queued_bytes.load(Ordering::Relaxed),
                )
            })
            .unwrap_or_default();
        let (queue_full, byte_budget_exceeded) = RECORDER
            .get()
            .and_then(Option::as_ref)
            .map(|r| {
                (
                    r.queue_full.load(Ordering::Relaxed),
                    r.byte_budget_exceeded.load(Ordering::Relaxed),
                )
            })
            .unwrap_or_default();
        let value = json!({"schema_version":1,"recorder_version":3,"written":self.written,"sequence":seq,"dropped":dropped,"queue_full":queue_full,"byte_budget_exceeded":byte_budget_exceeded,"io_errors":self.errors+producer_errors,"removed_chunks":self.removed,"filtered_unrelated_shreds":self.filtered,"pending_shreds":self.pending.len(),"queued_bytes":queued,"queue_item_limit":QUEUE_ITEMS,"queue_byte_limit":QUEUE_BYTES,"updated_us":now_us().to_string()});
        let temp = self.health_path.with_extension("tmp");
        if fs::write(&temp, value.to_string())
            .and_then(|_| fs::rename(temp, &self.health_path))
            .is_err()
        {
            self.errors += 1;
        }
    }
}
pub fn enabled() -> bool {
    recorder().is_some()
}
pub fn bytes(data: &[u8]) -> String {
    STANDARD.encode(data)
}
fn refresh(root: &PathBuf, selections: &Mutex<HashMap<String, Selection>>, control: &Mutex<Value>) {
    if let Ok(raw) = fs::read(root.join("control.json")) {
        if let Ok(value) = serde_json::from_slice(&raw) {
            if let Ok(mut current) = control.lock() {
                *current = value;
            }
        }
    }
    let known = match selections.lock() {
        Ok(v) => v.keys().cloned().collect::<std::collections::HashSet<_>>(),
        Err(_) => return,
    };
    let mut loaded = Vec::new();
    if let Ok(entries) = fs::read_dir(root.join("selections")) {
        for entry in entries.flatten().take(4096) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(signature) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if known.contains(signature) {
                continue;
            }
            if let Ok(raw) = fs::read(&path) {
                if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
                    if let (Some(run), Some(trace)) = (v["run_id"].as_str(), v["trace_id"].as_str())
                    {
                        loaded.push((
                            signature.to_string(),
                            Selection {
                                run: run.into(),
                                trace: trace.into(),
                            },
                        ));
                    }
                }
            }
        }
    }
    if let Ok(mut cache) = selections.lock() {
        cache.extend(loaded);
    }
}
fn selection(signature: &str) -> Option<Selection> {
    recorder()?.selections.lock().ok()?.get(signature).cloned()
}
pub fn selected(signature: &str) -> bool {
    selection(signature).is_some()
}
/// Client-only events before signing. Correlation uses the caller's run/trace IDs.
pub fn client(event: &str, data: Value, payload: Option<&[u8]>, source: &str) {
    if let (Ok(run), Ok(trace)) = (std::env::var("SOLK_TRACE_RUN"), std::env::var("SOLK_TRACE_ID")) {
        emit(event, None, Selection { run, trace }, data, payload, source);
    }
}
/// Client-only: registration is completed before the transaction is submitted.
pub fn register(signature: &str) {
    let Some(r) = recorder() else {
        return;
    };
    let (Ok(run), Ok(trace)) = (
        std::env::var("SOLK_TRACE_RUN"),
        std::env::var("SOLK_TRACE_ID"),
    ) else {
        return;
    };
    let dir = r.root.join("selections");
    let result = fs::create_dir_all(&dir).and_then(|_| {
        let path = dir.join(format!("{signature}.json"));
        let temp = path.with_extension(format!("{}-tmp", std::process::id()));
        fs::write(&temp, json!({"run_id":run,"trace_id":trace}).to_string())
            .and_then(|_| fs::rename(temp, path))
    });
    if result.is_err() {
        r.io_errors.fetch_add(1, Ordering::Relaxed);
    }
    refresh(&r.root, &r.selections, &r.control);
    // Allow other validators' background readers to observe this out-of-band selection.
    // This delay is exclusively in the lab CLI, outside validator critical paths.
    thread::sleep(Duration::from_millis(300));
}
fn emit(
    event: &str,
    signature: Option<&str>,
    selection: Selection,
    data: Value,
    payload: Option<&[u8]>,
    source: &str,
) {
    let Some(r) = recorder() else {
        return;
    };
    let sequence = r.seq.fetch_add(1, Ordering::Relaxed) + 1;
    let charge = (payload.map_or(0, <[u8]>::len) + data.to_string().len() + 1024) as u64;
    if r.queued_bytes.fetch_add(charge, Ordering::Relaxed) + charge > QUEUE_BYTES {
        r.queued_bytes.fetch_sub(charge, Ordering::Relaxed);
        r.byte_budget_exceeded.fetch_add(1, Ordering::Relaxed);
        r.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let payload = payload.map(|bytes| (format!("{:x}", Sha256::digest(bytes)), bytes.to_vec()));
    let context = CONTEXT.with(|c| c.borrow().clone());
    let value = json!({"schema_version":1,"event":event,"run_id":selection.run,"trace_id":selection.trace,
        "signature":signature,"node_id":r.node,"process_boot_id":r.boot,"process_type":std::env::var("SOLK_TRACE_PROCESS").unwrap_or_else(|_|"validator".into()),
        "sequence":sequence,"wall_us":now_us().to_string(),"mono_ns":r.start.elapsed().as_nanos().to_string(),
        "slot":data.get("slot").and_then(Value::as_u64).or(context.as_ref().map(|c|c.slot)),
        "bank_ref":context.as_ref().map(|c|format!("{}:{}:{}",r.node,r.boot,c.bank)),
        "execution_mode":context.as_ref().map(|c|c.mode.as_str()),"attempt_id":context.as_ref().map(|c|c.attempt.as_str()),
        "source":source,"data":data,"payload_ref":payload.as_ref().map(|(h,_)|h),"payload_size":payload.as_ref().map(|(_,b)|b.len())});
    if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
        r.sender.try_send(Item::Event(value, payload, charge))
    {
        r.queued_bytes.fetch_sub(charge, Ordering::Relaxed);
        r.queue_full.fetch_add(1, Ordering::Relaxed);
        r.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
pub fn tx(event: &str, signature: &str, data: Value, payload: Option<&[u8]>, source: &str) {
    if let Some(s) = selection(signature) {
        emit(event, Some(signature), s, data, payload, source);
    }
}
pub fn signature(wire: &[u8]) -> Option<String> {
    let mut count = 0usize;
    for (n, byte) in wire.iter().take(3).enumerate() {
        count |= ((byte & 127) as usize) << (n * 7);
        if byte & 128 == 0 {
            if count == 0
                || count > 65535
                || (n > 0 && byte & 127 == 0)
                || wire.len() < n + 1 + count * 64
            {
                return None;
            }
            return Some(bs58::encode(&wire[n + 1..n + 65]).into_string());
        }
    }
    None
}

pub fn wire(event: &str, wire: &[u8], data: Value, source: &str) {
    if !enabled() {
        return;
    }
    if let Some(signature) = signature(wire) {
        tx(event, &signature, data, Some(wire), source);
    }
}
pub fn slot(event: &str, slot: u64, mut data: Value, payload: Option<&[u8]>, source: &str) {
    let Some(r) = recorder() else {
        return;
    };
    let control = match r.control.lock() {
        Ok(v) => v.clone(),
        Err(_) => return,
    };
    if !control["enabled"].as_bool().unwrap_or(false)
        || slot < control["start_slot"].as_u64().unwrap_or(u64::MAX)
        || slot > control["end_slot"].as_u64().unwrap_or(0)
    {
        return;
    }
    data["slot"] = json!(slot);
    if let Some(run) = control["run_id"].as_str() {
        emit(
            event,
            None,
            Selection {
                run: run.into(),
                trace: String::new(),
            },
            data,
            payload,
            source,
        );
    }
}
pub struct Scope(Option<Context>);
impl Scope {
    pub fn new(signature: &str, slot: u64, bank: String) -> Self {
        let old = CONTEXT.with(|c| {
            if !selected(signature) {
                return c.replace(None);
            }
            let r = recorder().unwrap();
            let attempt = format!(
                "{}:{}",
                r.boot,
                r.attempts.fetch_add(1, Ordering::Relaxed) + 1
            );
            c.replace(Some(Context {
                signature: signature.into(),
                slot,
                bank,
                mode: MODE.with(|m| m.borrow().clone()),
                attempt,
            }))
        });
        Self(old)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CONTEXT.with(|c| {
            c.replace(self.0.take());
        });
    }
}
pub struct Mode(String);
pub fn mode(value: &str) -> Mode {
    Mode(MODE.with(|m| m.replace(value.into())))
}
impl Drop for Mode {
    fn drop(&mut self) {
        MODE.with(|m| {
            m.replace(self.0.clone());
        });
    }
}
pub fn current(event: &str, data: Value, payload: Option<&[u8]>, source: &str) {
    let c = CONTEXT.with(|c| c.borrow().clone());
    if let Some(c) = c {
        tx(event, &c.signature, data, payload, source);
    }
}
/// Call only outside validator critical paths (CLI exit, test tools).
pub fn flush() {
    if let Some(r) = recorder() {
        let (sender, receiver) = mpsc::channel();
        if r.sender.send(Item::Flush(sender)).is_ok() {
            let _ = receiver.recv_timeout(Duration::from_secs(3));
        }
    }
}

pub fn is_current() -> bool {
    CONTEXT.with(|c| c.borrow().is_some())
}
pub fn bank_id() -> String {
    BANK.with(|b| b.borrow().clone())
}
pub struct BankGuard(String);
pub fn bank(value: String) -> BankGuard {
    BankGuard(BANK.with(|b| b.replace(value)))
}
impl Drop for BankGuard {
    fn drop(&mut self) {
        BANK.with(|b| {
            b.replace(self.0.clone());
        });
    }
}

pub fn slot_enabled(slot: u64) -> bool {
    let Some(r) = recorder() else {
        return false;
    };
    let Ok(c) = r.control.lock() else {
        return false;
    };
    c["enabled"].as_bool().unwrap_or(false)
        && slot >= c["start_slot"].as_u64().unwrap_or(u64::MAX)
        && slot <= c["end_slot"].as_u64().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_queue_accepts_catchup_burst_without_a_consumer() {
        let (sender, _receiver) = mpsc::sync_channel(QUEUE_ITEMS);
        for _ in 0..32_768 {
            sender
                .try_send(Item::Event(Value::Null, None, 1024))
                .unwrap_or_else(|_| panic!("catch-up burst exhausted the queue"));
        }
        assert!(32_768 * 1024 < QUEUE_BYTES);
    }
    #[test]
    fn deferred_shreds_are_backfilled_only_for_the_selected_fec() {
        let root = std::env::temp_dir().join(format!("solk-fec-test-{}", now_us()));
        let dir = root.join("events");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(root.join("payloads")).unwrap();
        let mut writer = Writer::new(root.clone(), dir.clone(), dir.join("health.json"));
        let selected = json!({"event":"tvu.shred.verified","slot":12,"node_id":"test", "process_boot_id":"boot", "data":{"fec_set_index":32,"merkle_root":"root-a"}});
        let raw = vec![1, 2, 3];
        let hash = format!("{:x}", Sha256::digest(&raw));
        writer.accept(selected, Some((hash.clone(), raw.clone())), 0);
        writer.accept(json!({"event":"tvu.shred.verified","slot":12,"data":{"fec_set_index":64,"merkle_root":"root-b"}}), None, 0);
        assert_eq!(writer.pending.len(), 2);
        writer.accept(json!({"event":"broadcast.entry_batch","slot":12,"run_id":"run","data":{"shreds":[{"fec_set_index":32,"merkle_root":"root-a"}]}}), None, 0);
        writer.drain_pending();
        assert_eq!(writer.pending.len(), 1);
        writer.pending.front_mut().unwrap().0 = Instant::now() - Duration::from_secs(3);
        writer.drain_pending();
        writer.flush();
        assert_eq!(writer.written, 2);
        assert_eq!(writer.filtered, 1);
        assert_eq!(writer.errors, 0);
        assert_eq!(
            fs::read(root.join("payloads").join(format!("{hash}.bin"))).unwrap(),
            raw
        );
        assert!(fs::read_to_string(dir.join("events-000000.ndjson"))
            .unwrap()
            .contains("root-a"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn selected_capture_preserves_bytes_context_and_diagnostics() {
        let root = std::env::temp_dir().join(format!("solk-trace-test-{}", now_us()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("control.json"),
            json!({"enabled":true,"run_id":"test-run","start_slot":10,"end_slot":20}).to_string(),
        )
        .unwrap();
        std::env::set_var("SOLK_TRACE_DIR", &root);
        std::env::set_var("SOLK_TRACE_RUN", "test-run");
        std::env::set_var("SOLK_TRACE_ID", "test-trace");
        std::env::set_var("NODE", "test-node");
        let mut raw = vec![1u8];
        raw.extend_from_slice(&[7u8; 64]);
        raw.extend_from_slice(&[1, 0, 0, 0]);
        let sig = signature(&raw).unwrap();
        assert!(signature(&[0]).is_none());
        assert!(signature(&[255, 255, 255]).is_none());
        assert!(signature(&[1, 2, 3]).is_none());
        assert!(!selected(&sig));
        register(&sig);
        assert!(selected(&sig));
        assert!(slot_enabled(10));
        assert!(!slot_enabled(9));
        assert!(!slot_enabled(21));
        {
            let _mode = mode("leader");
            let _scope = Scope::new(&sig, 12, "bank-7".into());
            assert!(is_current());
            current(
                "test.execution",
                json!({"status":"ok"}),
                Some(&raw),
                file!(),
            );
        }
        assert!(!is_current());
        tx("test.ignored", "unknown", json!({}), None, file!());
        slot("test.slot", 12, json!({}), None, file!());
        flush();
        let dir = fs::read_dir(root.join("events"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let events = fs::read_to_string(dir.join("events-000000.ndjson"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["execution_mode"], "leader");
        assert_eq!(events[0]["signature"], sig);
        assert_eq!(events[0]["slot"], 12);
        let hash = events[0]["payload_ref"].as_str().unwrap();
        assert_eq!(
            fs::read(root.join("payloads").join(format!("{hash}.bin"))).unwrap(),
            raw
        );
        assert_eq!(hash, format!("{:x}", Sha256::digest(&raw)));
        let health: Value =
            serde_json::from_slice(&fs::read(dir.join("health.json")).unwrap()).unwrap();
        assert_eq!(health["written"], 2);
        assert_eq!(health["dropped"], 0);
        assert_eq!(health["io_errors"], 0);
        // The recorder thread is process-scoped; avoid deleting its live directory.
    }
}
