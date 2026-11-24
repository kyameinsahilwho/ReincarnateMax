//! Workspace queries: FileQuery -> SQL (filters, search, sort, paging), file rows and details,
//! the reconstructed folder tree (one GROUP BY folder, aggregated in memory, cached per session +
//! filter + change generation) and the per-category/status/condition counts.

use super::session::{self, db_err};
use super::writer::norm_folder;
use super::{Counts, FileDetail, FilePage, FileQuery, FileRow, FolderNode};
use crate::model::{Category, Condition, Extent, FileStatus, FoundFile, Origin};
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, Row};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------------ enum names

pub fn status_str(s: FileStatus) -> &'static str {
    match s {
        FileStatus::Deleted => "deleted",
        FileStatus::Existing => "existing",
        FileStatus::Lost => "lost",
        FileStatus::Carved => "carved",
        FileStatus::RecycleBin => "recycleBin",
    }
}
pub fn parse_status(s: &str) -> FileStatus {
    match s {
        "existing" => FileStatus::Existing,
        "lost" => FileStatus::Lost,
        "carved" => FileStatus::Carved,
        "recycleBin" => FileStatus::RecycleBin,
        _ => FileStatus::Deleted,
    }
}
pub fn origin_str(o: Origin) -> &'static str {
    match o {
        Origin::Ntfs => "ntfs",
        Origin::Fat => "fat",
        Origin::ExFat => "exFat",
        Origin::Carving => "carving",
        Origin::RecycleBin => "recycleBin",
    }
}
pub fn parse_origin(s: &str) -> Origin {
    match s {
        "fat" => Origin::Fat,
        "exFat" => Origin::ExFat,
        "carving" => Origin::Carving,
        "recycleBin" => Origin::RecycleBin,
        _ => Origin::Ntfs,
    }
}
pub fn condition_str(c: Condition) -> &'static str {
    match c {
        Condition::Excellent => "excellent",
        Condition::Good => "good",
        Condition::Partial => "partial",
        Condition::Unknown => "unknown",
    }
}
pub fn parse_condition(s: &str) -> Condition {
    match s {
        "excellent" => Condition::Excellent,
        "good" => Condition::Good,
        "partial" => Condition::Partial,
        _ => Condition::Unknown,
    }
}

// ---------------------------------------------------------------------------------- filters

pub struct Where {
    pub sql: String,
    pub params: Vec<Value>,
}

fn in_list(col: &str, vals: &[String], out: &mut Vec<String>, params: &mut Vec<Value>) {
    if vals.is_empty() {
        out.push("0".into()); // an explicitly empty selection matches nothing
        return;
    }
    let marks = vec!["?"; vals.len()].join(",");
    out.push(format!("{col} IN ({marks})"));
    params.extend(vals.iter().map(|v| Value::Text(v.clone())));
}

/// WHERE clause (always valid SQL, "1" when no filter). `with_folder` = apply folder/recursive.
pub fn build_where(q: &FileQuery, with_folder: bool) -> Where {
    let mut c: Vec<String> = Vec::new();
    let mut p: Vec<Value> = Vec::new();
    if with_folder {
        if let Some(folder) = &q.folder {
            let lc = norm_folder(folder).to_lowercase();
            if q.recursive.unwrap_or(false) {
                if !lc.is_empty() {
                    // '\' is 0x5C and ']' 0x5D: [lc\, lc]) is exactly "below lc", index-friendly.
                    c.push("(folder_lc = ? OR (folder_lc >= ? AND folder_lc < ?))".into());
                    p.push(Value::Text(lc.clone()));
                    p.push(Value::Text(format!("{lc}\\")));
                    p.push(Value::Text(format!("{lc}]")));
                }
            } else {
                c.push("folder_lc = ?".into());
                p.push(Value::Text(lc));
            }
        }
    }
    if let Some(s) = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let lc = s.to_lowercase();
        let ext = lc.strip_prefix("*.").or_else(|| lc.strip_prefix('.'));
        match ext {
            Some(e) if !e.is_empty() && e.len() <= 8 && e.chars().all(|ch| ch.is_alphanumeric()) => {
                c.push("ext = ?".into());
                p.push(Value::Text(e.to_string()));
            }
            _ if lc.contains('*') || lc.contains('?') => {
                c.push("name_lc GLOB ?".into());
                p.push(Value::Text(lc.replace('[', "[[]")));
            }
            _ => {
                c.push("instr(name_lc, ?) > 0".into());
                p.push(Value::Text(lc));
            }
        }
    }
    if let Some(v) = &q.categories {
        in_list("category", v, &mut c, &mut p);
    }
    if let Some(v) = &q.type_ids {
        let v: Vec<String> = v.iter().map(|s| s.to_ascii_lowercase()).collect();
        in_list("type_id", &v, &mut c, &mut p);
    }
    if let Some(v) = &q.statuses {
        in_list("status", v, &mut c, &mut p);
    }
    if let Some(v) = &q.conditions {
        in_list("condition", v, &mut c, &mut p);
    }
    if let Some(n) = q.min_size {
        c.push("size >= ?".into());
        p.push(Value::Integer(n.min(i64::MAX as u64) as i64));
    }
    if let Some(n) = q.max_size {
        c.push("size <= ?".into());
        p.push(Value::Integer(n.min(i64::MAX as u64) as i64));
    }
    let date_col = match q.date_field.as_deref() {
        Some("created") => "created",
        Some("deleted") => "deleted",
        _ => "modified",
    };
    if let Some(t) = q.date_from {
        c.push(format!("{date_col} >= ?"));
        p.push(Value::Integer(t));
    }
    if let Some(t) = q.date_to {
        c.push(format!("{date_col} <= ?"));
        p.push(Value::Integer(t));
    }
    if q.duplicates_only.unwrap_or(false) {
        c.push("dup_group IS NOT NULL".into());
    }
    Where { sql: if c.is_empty() { "1".into() } else { c.join(" AND ") }, params: p }
}

pub fn order_by(q: &FileQuery) -> String {
    let d = if q.desc.unwrap_or(false) { " DESC" } else { "" };
    let cols: &[&str] = match q.sort.as_deref() {
        Some("size") => &["size"],
        Some("modified") => &["modified"],
        Some("created") => &["created"],
        Some("deleted") => &["deleted"],
        Some("condition") => &["cond_rank"],
        Some("type") => &["type_id"],
        Some("folder") => &["folder_lc", "name_lc"],
        _ => &["name_lc"],
    };
    let mut s: Vec<String> = cols.iter().map(|c| format!("{c}{d}")).collect();
    s.push(format!("id{d}"));
    s.join(", ")
}

/// A cache key for the filter part of a query (no folder unless asked, no sort/paging).
fn filter_key(q: &FileQuery, with_folder: bool) -> String {
    let mut k = q.clone();
    k.sort = None;
    k.desc = None;
    k.offset = None;
    k.limit = None;
    if !with_folder {
        k.folder = None;
        k.recursive = None;
    }
    serde_json::to_string(&k).unwrap_or_default()
}

// ------------------------------------------------------------------------------------- rows

pub const ROW_COLS: &str = "id, name, folder, size, type_id, status, origin, condition, note, created, modified, deleted, fragmented, flags, dup_group, meta";

pub fn row_from(r: &Row) -> rusqlite::Result<FileRow> {
    let type_id: String = r.get(4)?;
    let meta: Option<String> = r.get(15)?;
    Ok(FileRow {
        id: r.get(0)?,
        name: r.get(1)?,
        folder: r.get(2)?,
        size: r.get::<_, i64>(3)?.max(0) as u64,
        category: crate::formats::category_of(&type_id),
        type_id,
        status: parse_status(&r.get::<_, String>(5)?),
        origin: parse_origin(&r.get::<_, String>(6)?),
        condition: parse_condition(&r.get::<_, String>(7)?),
        note: r.get(8)?,
        created: r.get(9)?,
        modified: r.get(10)?,
        deleted: r.get(11)?,
        fragmented: r.get::<_, i64>(12)? != 0,
        flags: r.get::<_, i64>(13)? as u32,
        dup_group: r.get(14)?,
        meta: meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or_default(),
    })
}

pub fn unpack_extents(b: &[u8]) -> Vec<Extent> {
    b.chunks_exact(16)
        .map(|c| Extent { offset: u64::from_le_bytes(c[..8].try_into().unwrap()), len: u64::from_le_bytes(c[8..].try_into().unwrap()) })
        .collect()
}

pub const FILE_COLS: &str =
    "id, name, folder, size, type_id, status, origin, condition, note, created, modified, accessed, deleted, fragmented, flags, fs_ref, meta, extents, resident, live_path";

/// A full FoundFile from a FILE_COLS row (id first).
pub fn file_from_row(r: &Row) -> rusqlite::Result<(i64, FoundFile)> {
    let meta: Option<String> = r.get(16)?;
    let ext: Option<Vec<u8>> = r.get(17)?;
    Ok((
        r.get(0)?,
        FoundFile {
            name: r.get(1)?,
            folder: r.get(2)?,
            size: r.get::<_, i64>(3)?.max(0) as u64,
            type_id: r.get(4)?,
            status: parse_status(&r.get::<_, String>(5)?),
            origin: parse_origin(&r.get::<_, String>(6)?),
            condition: parse_condition(&r.get::<_, String>(7)?),
            note: r.get(8)?,
            created: r.get(9)?,
            modified: r.get(10)?,
            accessed: r.get(11)?,
            deleted: r.get(12)?,
            fragmented: r.get::<_, i64>(13)? != 0,
            flags: r.get::<_, i64>(14)? as u32,
            fs_ref: r.get::<_, Option<i64>>(15)?.map(|v| v as u64),
            meta: meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or_default(),
            extents: ext.map(|b| unpack_extents(&b)).unwrap_or_default(),
            resident: r.get(18)?,
            live_path: r.get(19)?,
        },
    ))
}

pub fn get_file(c: &Connection, id: i64) -> Result<FoundFile, String> {
    use rusqlite::OptionalExtension;
    c.query_row(&format!("SELECT {FILE_COLS} FROM files WHERE id = ?1"), [id], file_from_row)
        .optional()
        .map_err(db_err)?
        .map(|(_, f)| f)
        .ok_or_else(|| "That file isn't in this scan session any more.".to_string())
}

// ---------------------------------------------------------------------------------- queries

/// (session, filter) -> (generation, computed at, how long it took, (files, bytes)).
type TotalsCache = Mutex<HashMap<(String, String), (u64, Instant, Duration, (u64, u64))>>;

fn totals_cache() -> &'static TotalsCache {
    static C: OnceLock<TotalsCache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// While a scan adds files every commit changes the generation, so caches keyed on it would miss
/// on every poll. A live result is reused for a while instead: at least `min`, and four times
/// what it took to compute (a slow query never keeps the session connection busy all the time).
fn live_fresh(at: Instant, took: Duration, min: Duration) -> bool {
    at.elapsed() < min.max(took * 4)
}

const LIVE_TOTALS: Duration = Duration::from_secs(2);
const LIVE_TREE: Duration = Duration::from_secs(3);

pub fn query_files(id: &str, c: &Connection, q: &FileQuery) -> Result<FilePage, String> {
    let w = build_where(q, true);
    let key = (id.to_string(), filter_key(q, true));
    let gen = session::gen(id);
    let live = super::jobs::running(id).is_some();
    let cached = totals_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .and_then(|&(g, at, took, t)| (g == gen || (live && live_fresh(at, took, LIVE_TOTALS))).then_some(t));
    let (total, total_size) = match cached {
        Some(t) => t,
        // No filter during a scan: the writer's running totals (kept in meta at every commit).
        None if live && w.params.is_empty() && w.sql == "1" => {
            let f = session::meta_get::<i64>(c, session::K_FILES).unwrap_or(0).max(0) as u64;
            let b = session::meta_get::<i64>(c, session::K_BYTES).unwrap_or(0).max(0) as u64;
            (f, b)
        }
        None => {
            let t0 = Instant::now();
            let t: (i64, i64) = c
                .query_row(&format!("SELECT count(*), coalesce(sum(size), 0) FROM files WHERE {}", w.sql), params_from_iter(w.params.iter()), |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(db_err)?;
            let t = (t.0.max(0) as u64, t.1.max(0) as u64);
            let mut m = totals_cache().lock().unwrap_or_else(|e| e.into_inner());
            if m.len() > 256 {
                m.clear();
            }
            m.insert(key, (gen, Instant::now(), t0.elapsed(), t));
            t
        }
    };
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let offset = q.offset.unwrap_or(0);
    let sql = format!("SELECT {ROW_COLS} FROM files WHERE {} ORDER BY {} LIMIT {limit} OFFSET {offset}", w.sql, order_by(q));
    let mut st = c.prepare_cached(&sql).map_err(db_err)?;
    let items = st.query_map(params_from_iter(w.params.iter()), row_from).map_err(db_err)?.collect::<Result<Vec<_>, _>>().map_err(db_err)?;
    Ok(FilePage { total, total_size, items })
}

/// Most ids the `query_ids` command hands to the UI ("select all").
pub const MAX_IDS: u64 = 1_000_000;

pub const TOO_MANY_IDS: &str =
    "There are more than 1,000,000 files here, too many to select one by one. Use Recover all instead, or narrow the list with a filter.";

/// Every matching id, in the query's sort order, with no limit (recovery and reports must see
/// every file).
pub fn query_ids(c: &Connection, q: &FileQuery) -> Result<Vec<i64>, String> {
    ids_with_limit(c, q, None)
}

/// [`query_ids`] for the UI: more than `max` matches is refused with a sentence instead of being
/// cut short silently.
pub fn query_ids_limited(c: &Connection, q: &FileQuery, max: u64) -> Result<Vec<i64>, String> {
    let ids = ids_with_limit(c, q, Some(max.saturating_add(1)))?;
    if ids.len() as u64 > max {
        return Err(TOO_MANY_IDS.into());
    }
    Ok(ids)
}

fn ids_with_limit(c: &Connection, q: &FileQuery, limit: Option<u64>) -> Result<Vec<i64>, String> {
    let w = build_where(q, true);
    let lim = limit.map(|n| format!(" LIMIT {}", n.min(i64::MAX as u64))).unwrap_or_default();
    let sql = format!("SELECT id FROM files WHERE {} ORDER BY {}{lim}", w.sql, order_by(q));
    let mut st = c.prepare_cached(&sql).map_err(db_err)?;
    let ids = st.query_map(params_from_iter(w.params.iter()), |r| r.get(0)).map_err(db_err)?.collect::<Result<Vec<i64>, _>>().map_err(db_err)?;
    Ok(ids)
}

pub fn file_detail(c: &Connection, id: i64) -> Result<FileDetail, String> {
    use rusqlite::OptionalExtension;
    let sql = format!("SELECT {ROW_COLS}, extents, accessed, fs_ref, resident IS NOT NULL, live_path, hash FROM files WHERE id = ?1");
    let d = c
        .query_row(&sql, [id], |r| {
            let row = row_from(r)?;
            let ext: Option<Vec<u8>> = r.get(16)?;
            Ok(FileDetail {
                row,
                extents: ext.map(|b| unpack_extents(&b)).unwrap_or_default(),
                accessed: r.get(17)?,
                fs_ref: r.get::<_, Option<i64>>(18)?.map(|v| v as u64),
                has_resident: r.get::<_, i64>(19)? != 0,
                live_path: r.get(20)?,
                hash: r.get(21)?,
                source: Default::default(),
                sector_size: 512,
            })
        })
        .optional()
        .map_err(db_err)?
        .ok_or_else(|| "That file isn't in this scan session any more.".to_string())?;
    let mut d = d;
    d.source = session::meta_json(c, session::K_SOURCE).unwrap_or_default();
    d.sector_size = session::meta_get::<i64>(c, session::K_SECTOR_SIZE).unwrap_or(512) as u32;
    Ok(d)
}

pub fn counts(c: &Connection) -> Result<Counts, String> {
    let mut out = Counts::default();
    let group = |col: &str| -> Result<Vec<(String, u64, u64)>, String> {
        let mut st = c.prepare(&format!("SELECT {col}, count(*), coalesce(sum(size), 0) FROM files GROUP BY {col}")).map_err(db_err)?;
        let rows = st
            .query_map([], |r| {
                let k: Value = r.get(0)?;
                let k = match k {
                    Value::Integer(i) => i.to_string(),
                    Value::Text(t) => t,
                    _ => String::new(),
                };
                Ok((k, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    };
    for (k, n, b) in group("category")? {
        let k = Category::parse(&k).map(|c| c.as_str().to_string()).unwrap_or(k);
        out.by_category.insert(k, (n, b));
    }
    for (k, n, b) in group("status")? {
        out.by_status.insert(k, (n, b));
    }
    for (k, n, b) in group("cond_rank")? {
        let name = match k.as_str() {
            "0" => "excellent",
            "1" => "good",
            "3" => "partial",
            _ => "unknown",
        };
        let e = out.by_condition.entry(name.to_string()).or_insert((0, 0));
        e.0 += n;
        e.1 += b;
    }
    Ok(out)
}

// ------------------------------------------------------------------------------ folder tree

#[derive(Default)]
pub struct TreeNode {
    pub name: String,
    pub path: String,
    pub files: u64,
    pub size: u64,
    pub children: Vec<String>,
}

pub type Tree = HashMap<String, TreeNode>;

/// (session, filter) -> (generation, built at, how long it took, tree).
type TreeCache = Mutex<HashMap<(String, String), (u64, Instant, Duration, Arc<Tree>)>>;

fn tree_cache() -> &'static TreeCache {
    static C: OnceLock<TreeCache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Folders that sort after the regular ones at the top level.
fn special_rank(lc: &str) -> u8 {
    match lc {
        "\\$recycle.bin" => 1,
        "\\lost folders" => 2,
        "\\found by signature" => 3,
        _ => 0,
    }
}

pub fn build_tree(c: &Connection, q: Option<&FileQuery>) -> Result<Tree, String> {
    let empty = FileQuery::default();
    let w = build_where(q.unwrap_or(&empty), false);
    let sql = tree_sql(c, &w.sql);
    let mut st = c.prepare(&sql).map_err(db_err)?;
    let mut rows = st.query(params_from_iter(w.params.iter())).map_err(db_err)?;
    let mut tree: Tree = HashMap::new();
    tree.insert(String::new(), TreeNode::default());
    while let Some(r) = rows.next().map_err(db_err)? {
        let lc: String = r.get(0).map_err(db_err)?;
        let disp: String = r.get(1).map_err(db_err)?;
        let n = r.get::<_, i64>(2).map_err(db_err)? as u64;
        let b = r.get::<_, i64>(3).map_err(db_err)? as u64;
        {
            let root = tree.get_mut("").unwrap();
            root.files += n;
            root.size += b;
        }
        if lc.is_empty() {
            continue;
        }
        // Walk "\a\b\c": "\a", "\a\b", "\a\b\c".
        let lc_parts: Vec<&str> = lc.split('\\').filter(|s| !s.is_empty()).collect();
        let d_parts: Vec<&str> = disp.split('\\').filter(|s| !s.is_empty()).collect();
        let mut parent = String::new();
        let mut path_lc = String::new();
        let mut path_disp = String::new();
        for (i, part) in lc_parts.iter().enumerate() {
            path_lc.push('\\');
            path_lc.push_str(part);
            path_disp.push('\\');
            path_disp.push_str(d_parts.get(i).copied().unwrap_or(part));
            if !tree.contains_key(&path_lc) {
                let name = d_parts.get(i).copied().unwrap_or(part).to_string();
                tree.insert(path_lc.clone(), TreeNode { name, path: path_disp.clone(), ..Default::default() });
                if let Some(pn) = tree.get_mut(&parent) {
                    pn.children.push(path_lc.clone());
                }
            }
            let node = tree.get_mut(&path_lc).unwrap();
            node.files += n;
            node.size += b;
            parent = path_lc.clone();
        }
    }
    Ok(tree)
}

/// The folder-tree query. With the folder index: group on the covering (folder_lc, size) index,
/// then one indexed lookup per folder for its display spelling (min(folder) in the GROUP BY would
/// visit every row). During a scan the indexes are dropped and that lookup would scan the table
/// once per folder, so the spelling is aggregated in the same single pass instead.
pub fn tree_sql(c: &Connection, filter: &str) -> String {
    if has_folder_index(c) {
        format!(
            "SELECT g.folder_lc, (SELECT x.folder FROM files x WHERE x.folder_lc = g.folder_lc LIMIT 1), g.n, g.b
             FROM (SELECT folder_lc, count(*) AS n, coalesce(sum(size), 0) AS b FROM files WHERE {filter} GROUP BY folder_lc) g"
        )
    } else {
        format!("SELECT folder_lc, min(folder), count(*), coalesce(sum(size), 0) FROM files WHERE {filter} GROUP BY folder_lc")
    }
}

fn has_folder_index(c: &Connection) -> bool {
    c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'files_folder'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0
}

pub fn folder_children(id: &str, c: &Connection, parent: &str, q: Option<&FileQuery>) -> Result<Vec<FolderNode>, String> {
    let fkey = q.map(|q| filter_key(q, false)).unwrap_or_default();
    let key = (id.to_string(), fkey);
    let gen = session::gen(id);
    // While a scan is still adding files the tree may be a few seconds old instead of being
    // rebuilt on every commit.
    let live = super::jobs::running(id).is_some();
    let cached = tree_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .and_then(|(g, at, took, t)| (*g == gen || (live && live_fresh(*at, *took, LIVE_TREE))).then(|| t.clone()));
    let tree = match cached {
        Some(t) => t,
        None => {
            let t0 = Instant::now();
            let t = Arc::new(build_tree(c, q)?);
            let mut m = tree_cache().lock().unwrap_or_else(|e| e.into_inner());
            if m.len() > 32 {
                m.clear();
            }
            m.insert(key, (gen, Instant::now(), t0.elapsed(), t.clone()));
            t
        }
    };
    let p = norm_folder(parent).to_lowercase();
    let Some(node) = tree.get(&p) else { return Ok(Vec::new()) };
    let mut kids: Vec<(&String, &TreeNode)> = node.children.iter().filter_map(|k| tree.get(k).map(|n| (k, n))).collect();
    let top = p.is_empty();
    kids.sort_by(|a, b| {
        let ra = if top { special_rank(a.0) } else { 0 };
        let rb = if top { special_rank(b.0) } else { 0 };
        ra.cmp(&rb).then_with(|| a.0.cmp(b.0))
    });
    Ok(kids
        .into_iter()
        .map(|(_, n)| FolderNode { path: n.path.clone(), name: n.name.clone(), files: n.files, size: n.size, has_children: !n.children.is_empty() })
        .collect())
}

/// Merge meta keys into a file's meta JSON.
pub fn merge_meta(c: &Connection, id: i64, add: &BTreeMap<String, String>) -> Result<(), String> {
    use rusqlite::OptionalExtension;
    let cur: Option<Option<String>> = c.query_row("SELECT meta FROM files WHERE id = ?1", [id], |r| r.get(0)).optional().map_err(db_err)?;
    let Some(cur) = cur else { return Err("That file isn't in this scan session any more.".into()) };
    let mut m: BTreeMap<String, String> = cur.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    m.extend(add.iter().map(|(k, v)| (k.clone(), v.clone())));
    let s = serde_json::to_string(&m).unwrap_or_default();
    c.execute("UPDATE files SET meta = ?2 WHERE id = ?1", rusqlite::params![id, s]).map_err(|_| session::WRITE_FAILED.to_string())?;
    Ok(())
}
