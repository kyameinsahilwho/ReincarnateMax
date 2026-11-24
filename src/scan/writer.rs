//! One writer thread per running session: batches file inserts, condition updates, log lines and
//! meta changes into transactions (every 2000 rows or 300 ms), keeps the file count / byte total /
//! longest extent in meta, and bumps the session's change generation after each commit.

use super::session::{self, K_BYTES, K_FILES, K_MAX_EXTENT};
use crate::model::{flags, Condition, FoundFile, LogLevel, SPARSE};
use rusqlite::types::Value;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct CondUpdate {
    pub id: i64,
    pub condition: Condition,
    pub note: String,
    pub flags: u32,
    pub type_id: String,
}

pub enum Msg {
    /// A found file, the pipeline stage code that reported it and the sweep segment start.
    File(Box<FoundFile>, u8, u64),
    Update(Box<CondUpdate>),
    Log(i64, LogLevel, String),
    Meta(String, Value),
    Flush(SyncSender<()>),
    /// Build (true) or drop (false) the secondary indexes.
    Indexes(bool),
    Stop,
}

pub struct Writer {
    pub tx: SyncSender<Msg>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// First write error (disk full…), as a sentence.
    pub error: Arc<Mutex<Option<String>>>,
}

const BATCH_ROWS: usize = 2000;
const BATCH_TIME: Duration = Duration::from_millis(300);

impl Writer {
    pub fn spawn(id: &str, path: PathBuf) -> Result<Arc<Writer>, String> {
        let conn = session::open_path(&path, false)?;
        let (tx, rx) = sync_channel::<Msg>(16_384);
        let error = Arc::new(Mutex::new(None));
        let err2 = error.clone();
        let sid = id.to_string();
        let handle = std::thread::Builder::new()
            .name(format!("max-scan-db-{id}"))
            .spawn(move || run(sid, conn, rx, err2))
            .map_err(|_| "MAX couldn't start the scan.".to_string())?;
        Ok(Arc::new(Writer { tx, handle: Mutex::new(Some(handle)), error }))
    }

    pub fn send(&self, m: Msg) {
        let _ = self.tx.send(m);
    }

    pub fn meta(&self, key: &str, v: impl rusqlite::ToSql) {
        use rusqlite::types::ToSqlOutput;
        let v = match v.to_sql() {
            Ok(ToSqlOutput::Owned(v)) => v,
            Ok(ToSqlOutput::Borrowed(r)) => Value::from(r),
            _ => Value::Null,
        };
        self.send(Msg::Meta(key.to_string(), v));
    }

    /// Commit everything sent so far and wait for it.
    pub fn flush(&self) {
        let (t, r) = sync_channel(1);
        if self.tx.send(Msg::Flush(t)).is_ok() {
            let _ = r.recv();
        }
    }

    /// Commit and end the thread.
    pub fn stop(&self) {
        let _ = self.tx.send(Msg::Stop);
        if let Some(h) = self.handle.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = h.join();
        }
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

struct State {
    id: String,
    files: i64,
    bytes: i64,
    max_extent: i64,
    dirty_totals: bool,
    changed: bool,
}

fn totals(c: &Connection) -> (i64, i64, i64) {
    let (f, b) = c.query_row("SELECT count(*), coalesce(sum(size), 0) FROM files", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((0, 0));
    let m = c.query_row("SELECT coalesce(max(end_off - start_off), 0) FROM file_extents", [], |r| r.get(0)).unwrap_or(0);
    (f, b, m)
}

fn run(id: String, conn: Connection, rx: Receiver<Msg>, error: Arc<Mutex<Option<String>>>) {
    let (files, bytes, max_extent) = totals(&conn);
    let mut st = State { id, files, bytes, max_extent, dirty_totals: false, changed: false };
    let mut in_tx = false;
    let mut began = Instant::now();
    let mut rows = 0usize;
    let fail = |e: rusqlite::Error| {
        tracing::warn!("session write failed: {e}");
        let mut g = error.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(session::WRITE_FAILED.to_string());
        }
    };
    let commit = |conn: &Connection, st: &mut State, in_tx: &mut bool| {
        if !*in_tx {
            return;
        }
        if st.dirty_totals {
            let r = (|| -> rusqlite::Result<()> {
                for (k, v) in [(K_FILES, st.files), (K_BYTES, st.bytes), (K_MAX_EXTENT, st.max_extent)] {
                    conn.execute("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![k, v])?;
                }
                Ok(())
            })();
            if let Err(e) = r {
                fail(e);
            }
            st.dirty_totals = false;
        }
        if let Err(e) = conn.execute_batch("COMMIT") {
            fail(e);
            let _ = conn.execute_batch("ROLLBACK");
        }
        *in_tx = false;
        if st.changed {
            session::bump(&st.id);
            st.changed = false;
        }
    };
    loop {
        let wait = if in_tx { BATCH_TIME.saturating_sub(began.elapsed()) } else { Duration::from_secs(3600) };
        let msg = match rx.recv_timeout(wait) {
            Ok(m) => m,
            Err(RecvTimeoutError::Timeout) => {
                commit(&conn, &mut st, &mut in_tx);
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                commit(&conn, &mut st, &mut in_tx);
                break;
            }
        };
        match msg {
            Msg::Flush(ack) => {
                commit(&conn, &mut st, &mut in_tx);
                let _ = ack.send(());
                continue;
            }
            Msg::Stop => {
                commit(&conn, &mut st, &mut in_tx);
                break;
            }
            Msg::Indexes(build) => {
                commit(&conn, &mut st, &mut in_tx);
                let r = if build { session::create_indexes(&conn) } else { session::drop_indexes(&conn) };
                if let Err(e) = r {
                    fail(e);
                }
                continue;
            }
            other => {
                if !in_tx {
                    if let Err(e) = conn.execute_batch("BEGIN") {
                        fail(e);
                        continue;
                    }
                    in_tx = true;
                    began = Instant::now();
                    rows = 0;
                }
                if let Err(e) = apply(&conn, &mut st, other) {
                    fail(e);
                }
                rows += 1;
                if rows >= BATCH_ROWS || began.elapsed() >= BATCH_TIME {
                    commit(&conn, &mut st, &mut in_tx);
                }
            }
        }
    }
}

fn apply(c: &Connection, st: &mut State, m: Msg) -> rusqlite::Result<()> {
    match m {
        Msg::File(f, stage, seg) => {
            let id = insert_file(c, &f, stage, seg)?;
            for e in &f.extents {
                if e.offset != SPARSE && e.len > 0 {
                    let end = e.offset.saturating_add(e.len);
                    c.prepare_cached("INSERT INTO file_extents(start_off, end_off, file_id) VALUES (?1, ?2, ?3)")?.execute(params![e.offset as i64, end as i64, id])?;
                    st.max_extent = st.max_extent.max(e.len as i64);
                }
            }
            st.files += 1;
            st.bytes += f.size as i64;
            st.dirty_totals = true;
            st.changed = true;
        }
        Msg::Update(u) => {
            c.prepare_cached("UPDATE files SET condition = ?2, cond_rank = ?3, note = ?4, flags = ?5, type_id = ?6, category = ?7 WHERE id = ?1")?.execute(params![
                u.id,
                super::query::condition_str(u.condition),
                u.condition.rank() as i64,
                u.note,
                u.flags as i64,
                u.type_id,
                crate::formats::category_of(&u.type_id).as_str(),
            ])?;
            st.changed = true;
        }
        Msg::Log(at, level, msg) => {
            c.prepare_cached("INSERT INTO log(at, level, message) VALUES (?1, ?2, ?3)")?.execute(params![at, level_str(level), msg])?;
        }
        Msg::Meta(k, v) => {
            c.prepare_cached("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value")?.execute(params![k, v])?;
        }
        Msg::Flush(_) | Msg::Stop | Msg::Indexes(_) => {}
    }
    Ok(())
}

pub fn level_str(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

/// Normalised folder: backslashes, leading "\", no trailing "\", "" for the root.
pub fn norm_folder(s: &str) -> String {
    let t = s.trim().replace('/', "\\");
    let t = t.trim_end_matches('\\');
    if t.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(t.len() + 1);
    if !t.starts_with('\\') {
        out.push('\\');
    }
    // Collapse doubled separators.
    let mut prev_sep = false;
    for ch in t.chars() {
        if ch == '\\' {
            if prev_sep {
                continue;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
        out.push(ch);
    }
    out
}

pub fn pack_extents(f: &FoundFile) -> Vec<u8> {
    let mut v = Vec::with_capacity(f.extents.len() * 16);
    for e in &f.extents {
        v.extend_from_slice(&e.offset.to_le_bytes());
        v.extend_from_slice(&e.len.to_le_bytes());
    }
    v
}

pub fn insert_file(c: &Connection, f: &FoundFile, stage: u8, seg: u64) -> rusqlite::Result<i64> {
    let folder = norm_folder(&f.folder);
    let meta = if f.meta.is_empty() { None } else { serde_json::to_string(&f.meta).ok() };
    let type_id = f.type_id.to_ascii_lowercase();
    c.prepare_cached(
        "INSERT INTO files(name, name_lc, folder, folder_lc, ext, type_id, category, size, status, origin, condition, cond_rank, note,
          created, modified, accessed, deleted, fragmented, flags, fs_ref, meta, extents, resident, live_path, first_off, stage, seg)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)",
    )?
    .execute(params![
        f.name,
        f.name.to_lowercase(),
        folder,
        folder.to_lowercase(),
        f.ext(),
        type_id,
        crate::formats::category_of(&type_id).as_str(),
        f.size as i64,
        super::query::status_str(f.status),
        super::query::origin_str(f.origin),
        super::query::condition_str(f.condition),
        f.condition.rank() as i64,
        f.note,
        f.created,
        f.modified,
        f.accessed,
        f.deleted,
        f.fragmented as i64,
        f.flags as i64,
        f.fs_ref.map(|r| r as i64),
        meta,
        pack_extents(f),
        f.resident.as_deref(),
        f.live_path.as_deref(),
        f.first_offset().map(|o| o as i64),
        stage as i64,
        seg as i64,
    ])?;
    Ok(c.last_insert_rowid())
}

/// Flags a file gets from its source (Volume Shadow Copies).
pub fn source_flags(kind: crate::model::SourceKind) -> u32 {
    if kind == crate::model::SourceKind::Snapshot {
        flags::SNAPSHOT
    } else {
        0
    }
}
