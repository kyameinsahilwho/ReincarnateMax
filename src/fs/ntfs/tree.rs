//! Folder-path reconstruction. Directory nodes point at their (already validated) parent; a node
//! whose parent is missing, reused or part of a loop becomes the top of a lost tree under
//! `\Lost folders`, keeping its own name: `\Lost folders\Holiday (folder 1234)\Day 1`.

use std::collections::{HashMap, HashSet};

pub const LOST: &str = "\\Lost folders";

#[derive(Clone, Debug, Default)]
pub struct Node {
    pub name: String,
    /// Key of the parent node, `None` when the parent is missing / reused / mismatched.
    pub parent: Option<u64>,
    /// Record number shown in lost-folder names.
    pub label: u64,
    /// Fixed path ("" for the root, the original folder for a recycled `$R` folder).
    pub fixed: Option<String>,
}

#[derive(Default)]
pub struct Tree {
    pub nodes: HashMap<u64, Node>,
    cache: HashMap<u64, (String, bool)>,
    /// Distinct tops of lost trees used so far.
    pub lost_roots: HashSet<String>,
}

/// A name usable as one path component.
pub fn component(name: &str) -> String {
    name.chars().map(|c| if c == '\\' || c == '\0' { '_' } else { c }).collect()
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: u64, node: Node) {
        self.nodes.insert(key, node);
    }

    fn lost_top(&mut self, key: u64) -> (String, bool) {
        let n = &self.nodes[&key];
        let p = if n.name.is_empty() { format!("{LOST}\\Folder {}", n.label) } else { format!("{LOST}\\{} (folder {})", component(&n.name), n.label) };
        self.lost_roots.insert(p.clone());
        (p, true)
    }

    /// Full path of directory `key` and whether it hangs under `\Lost folders`.
    pub fn dir_path(&mut self, key: u64) -> (String, bool) {
        if let Some(c) = self.cache.get(&key) {
            return c.clone();
        }
        if !self.nodes.contains_key(&key) {
            let p = format!("{LOST}\\Folder {key}");
            self.lost_roots.insert(p.clone());
            return (p, true);
        }
        let mut chain: Vec<u64> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut cur = key;
        let mut base: (String, bool);
        loop {
            if let Some(c) = self.cache.get(&cur) {
                base = c.clone();
                break;
            }
            let node = &self.nodes[&cur];
            if let Some(f) = &node.fixed {
                base = (f.clone(), false);
                self.cache.insert(cur, base.clone());
                break;
            }
            if !seen.insert(cur) || chain.len() > 4096 {
                // A loop (or an absurd depth): `cur` becomes the top of a lost tree.
                if let Some(i) = chain.iter().position(|&k| k == cur) {
                    chain.truncate(i);
                }
                base = self.lost_top(cur);
                self.cache.insert(cur, base.clone());
                break;
            }
            chain.push(cur);
            match node.parent {
                Some(p) if self.nodes.contains_key(&p) => cur = p,
                _ => {
                    chain.pop();
                    base = self.lost_top(cur);
                    self.cache.insert(cur, base.clone());
                    break;
                }
            }
        }
        for &k in chain.iter().rev() {
            let n = &self.nodes[&k];
            let name = if n.name.is_empty() { format!("Folder {}", n.label) } else { component(&n.name) };
            let p = (format!("{}\\{}", base.0, name), base.1);
            self.cache.insert(k, p.clone());
            base = p;
        }
        self.cache.get(&key).cloned().unwrap_or(base)
    }

    /// Folder for a file whose parent is `parent` (validated key) or, if `None`, the record
    /// `label` that no longer holds its folder.
    pub fn folder_for(&mut self, parent: Option<u64>, label: u64) -> (String, bool) {
        match parent {
            Some(k) if self.nodes.contains_key(&k) => self.dir_path(k),
            _ => {
                let p = format!("{LOST}\\Folder {label}");
                self.lost_roots.insert(p.clone());
                (p, true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, parent: Option<u64>, label: u64) -> Node {
        Node { name: name.into(), parent, label, fixed: None }
    }

    #[test]
    fn builds_paths_lost_trees_and_survives_loops() {
        let mut t = Tree::new();
        t.insert(5, Node { fixed: Some(String::new()), label: 5, ..Default::default() });
        t.insert(30, node("Users", Some(5), 30));
        t.insert(31, node("Ann", Some(30), 31));
        t.insert(32, node("Pictures", Some(31), 32));
        // Holiday's parent is gone; Day 1 lives inside it.
        t.insert(40, node("Holiday", None, 40));
        t.insert(41, node("Day 1", Some(40), 41));
        // A loop: 50 -> 51 -> 50.
        t.insert(50, node("A", Some(51), 50));
        t.insert(51, node("B", Some(50), 51));
        // Parent key that doesn't exist.
        t.insert(60, node("Orphan", Some(999), 60));

        assert_eq!(t.dir_path(32), ("\\Users\\Ann\\Pictures".to_string(), false));
        assert_eq!(t.dir_path(5), (String::new(), false));
        assert_eq!(t.dir_path(41), ("\\Lost folders\\Holiday (folder 40)\\Day 1".to_string(), true));
        let (a, lost) = t.dir_path(50);
        assert!(lost);
        assert_eq!(a, "\\Lost folders\\A (folder 50)");
        assert_eq!(t.dir_path(51).0, "\\Lost folders\\A (folder 50)\\B");
        assert_eq!(t.dir_path(60).0, "\\Lost folders\\Orphan (folder 60)");
        assert_eq!(t.folder_for(None, 1234), ("\\Lost folders\\Folder 1234".to_string(), true));
        assert_eq!(t.folder_for(Some(31), 31).0, "\\Users\\Ann");
        assert_eq!(t.lost_roots.len(), 4);
    }

    #[test]
    fn fixed_paths_override_and_names_are_cleaned() {
        let mut t = Tree::new();
        t.insert(5, Node { fixed: Some(String::new()), label: 5, ..Default::default() });
        t.insert(70, Node { name: "$RXYZ".into(), parent: Some(5), label: 70, fixed: Some("\\Users\\Ann\\Old stuff".into()) });
        t.insert(71, node("a\\b", Some(70), 71));
        t.insert(72, node("", Some(5), 72));
        assert_eq!(t.dir_path(71).0, "\\Users\\Ann\\Old stuff\\a_b");
        assert_eq!(t.dir_path(72).0, "\\Folder 72");
    }
}
