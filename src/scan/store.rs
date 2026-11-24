//! Session store API used by other modules (content, recover). OWNER: scan agent.
//! Signatures are contract; bodies are the scan agent's.

use super::session::{self, db_err, with_conn, WRITE_FAILED};
use crate::device::source::Source;
use crate::model::{Condition, FoundFile, LogLevel, SourceRef};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

pub fn session_source_ref(session: &str) -> Result<SourceRef, String> {
    if let Some(j) = super::jobs::running(session) {
        return Ok(j.source.clone());
    }
    with_conn(session, |c| session::meta_json(c, session::K_SOURCE).ok_or_else(|| session::DAMAGED.to_string()))
}

fn sources() -> &'static Mutex<HashMap<String, Source>> {
    static S: OnceLock<Mutex<HashMap<String, Source>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn forget_source(session: &str) {
    sources().lock().unwrap_or_else(|e| e.into_inner()).remove(session);
}

/// The session's source, opened read-only (cached per session; reopened if it went away).
pub fn open_session_source(session: &str) -> Result<Source, String> {
    if let Some(j) = super::jobs::running(session) {
        return Ok(j.src.clone());
    }
    let cached = sources().lock().unwrap_or_else(|e| e.into_inner()).get(session).cloned();
    if let Some(s) = cached {
        // A removed USB drive or closed image fails even a one-sector read: reopen it then.
        let mut b = vec![0u8; s.sector_size().clamp(512, 4096) as usize];
        if s.read_at(0, &mut b).is_ok() {
            return Ok(s);
        }
        forget_source(session);
    }
    let r = session_source_ref(session)?;
    let src = super::jobs::open(&r)?;
    let expected = with_conn(session, |c| Ok(session::meta_get::<i64>(c, session::K_SOURCE_LEN).unwrap_or(0)))? as u64;
    if expected != 0 && src.len() != expected {
        return Err("This drive's size changed since it was scanned, so its files can't be read safely. Scan it again.".into());
    }
    let mut m = sources().lock().unwrap_or_else(|e| e.into_inner());
    if m.len() > 16 {
        m.clear();
    }
    m.insert(session.to_string(), src.clone());
    Ok(src)
}

pub fn get_file(session: &str, id: i64) -> Result<FoundFile, String> {
    with_conn(session, |c| super::query::get_file(c, id))
}

pub fn query_ids(session: &str, q: &super::FileQuery) -> Result<Vec<i64>, String> {
    with_conn(session, |c| super::query::query_ids(c, q))
}

/// Set condition + note; `set_flags` bits are OR-ed into flags.
pub fn update_condition(session: &str, id: i64, condition: Condition, note: &str, set_flags: u32) -> Result<(), String> {
    with_conn(session, |c| {
        c.execute(
            "UPDATE files SET condition = ?2, cond_rank = ?3, note = ?4, flags = flags | ?5 WHERE id = ?1",
            rusqlite::params![id, super::query::condition_str(condition), condition.rank() as i64, note, set_flags as i64],
        )
        .map_err(|_| WRITE_FAILED.to_string())
    })?;
    session::bump(session);
    Ok(())
}

/// Merge keys into the file's meta.
pub fn update_meta(session: &str, id: i64, meta: &BTreeMap<String, String>) -> Result<(), String> {
    with_conn(session, |c| super::query::merge_meta(c, id, meta))?;
    session::bump(session);
    Ok(())
}

/// Content hash (BLAKE3 hex) for duplicate detection / verification.
pub fn set_hash(session: &str, id: i64, hash: &str) -> Result<(), String> {
    with_conn(session, |c| c.execute("UPDATE files SET hash = ?2 WHERE id = ?1", rusqlite::params![id, hash]).map_err(|_| WRITE_FAILED.to_string()))?;
    Ok(())
}

/// Replace all duplicate groups: (file id, group id). Files not listed get no group.
pub fn set_dup_groups(session: &str, groups: &[(i64, i64)]) -> Result<(), String> {
    with_conn(session, |c| {
        let r = (|| -> rusqlite::Result<()> {
            c.execute_batch("BEGIN")?;
            c.execute("UPDATE files SET dup_group = NULL WHERE dup_group IS NOT NULL", [])?;
            {
                let mut st = c.prepare_cached("UPDATE files SET dup_group = ?2 WHERE id = ?1")?;
                for &(id, g) in groups {
                    st.execute(rusqlite::params![id, g])?;
                }
            }
            c.execute_batch("COMMIT")
        })();
        if r.is_err() {
            let _ = c.execute_batch("ROLLBACK");
            return Err(WRITE_FAILED.to_string());
        }
        Ok(())
    })?;
    session::bump(session);
    Ok(())
}

/// (id, size, hash) of every file, for duplicate detection.
pub fn sizes_and_hashes(session: &str) -> Result<Vec<(i64, u64, Option<String>)>, String> {
    with_conn(session, |c| {
        let mut st = c.prepare_cached("SELECT id, size, hash FROM files ORDER BY id").map_err(db_err)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?.max(0) as u64, r.get::<_, Option<String>>(2)?))).map_err(db_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
    })
}

/// Append to the session log.
pub fn log(session: &str, level: LogLevel, msg: &str) {
    if let Some(j) = super::jobs::running(session) {
        j.writer.send(super::writer::Msg::Log(crate::model::now_ms(), level, msg.to_string()));
        return;
    }
    let _ = with_conn(session, |c| {
        c.execute(
            "INSERT INTO log(at, level, message) VALUES (?1, ?2, ?3)",
            rusqlite::params![crate::model::now_ms(), super::writer::level_str(level), msg],
        )
        .map_err(|_| WRITE_FAILED.to_string())
    });
}

/// Sizes of `ids` in one pass (missing ids are skipped), for destination checks on big selections
/// (one query per 900 ids instead of one `get_file` per file).
pub fn sizes_of(session: &str, ids: &[i64]) -> Result<Vec<u64>, String> {
    with_conn(session, |c| {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(900) {
            let marks = vec!["?"; chunk.len()].join(",");
            let mut st = c.prepare(&format!("SELECT size FROM files WHERE id IN ({marks})")).map_err(db_err)?;
            let rows = st.query_map(rusqlite::params_from_iter(chunk.iter()), |r| r.get::<_, i64>(0)).map_err(db_err)?;
            for r in rows {
                out.push(r.map_err(db_err)?.max(0) as u64);
            }
        }
        Ok(out)
    })
}
