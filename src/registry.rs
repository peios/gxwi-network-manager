//! The registry, as this program reads and writes it: a key read whole as a
//! tree of values and subkeys, and changes to several keys made as one.
//!
//! Everything Network Manager configures is under `Machine\System\Network`,
//! read by the kernel (the packet layers, port reservations), netd (the
//! interface layer, profiles, networks) and resolvd (`Dns`). A rule is
//! several values, and the kernel re-walks a moment after any change, so a
//! rule written value by value could be seen half-written: an `Actions`
//! before the conditions that narrow it is, for that moment, a rule that
//! matches everything. Every change here is a [`Batch`], one transaction,
//! seen whole or not at all.

use peios::registry::{CreateFlags, Key, KeyAccess, OpenFlags, Transaction, ValueType};

/// A registry value, as the vocabulary has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Str(String),
    List(Vec<String>),
    /// A descriptor, or anything else kept as bytes.
    Bytes(Vec<u8>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The value as a list: a list as it is, one string as a list of one.
    pub fn as_list(&self) -> Option<Vec<String>> {
        match self {
            Value::List(items) => Some(items.clone()),
            Value::Str(s) => Some(vec![s.clone()]),
            Value::Int(i) => Some(vec![i.to_string()]),
            Value::Bytes(_) => None,
        }
    }

    /// The value as a number, from a number or the decimal string of one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// The value as the text a person reads and writes it in: a list's
    /// items joined by commas.
    pub fn text(&self) -> String {
        match self {
            Value::Int(i) => i.to_string(),
            Value::Str(s) => s.clone(),
            Value::List(items) => items.join(", "),
            Value::Bytes(b) => format!("{} bytes", b.len()),
        }
    }

    fn encode(&self) -> (ValueType, Vec<u8>) {
        match self {
            Value::Int(i) if (0..=i64::from(u32::MAX)).contains(i) => (ValueType::DWORD, (*i as u32).to_le_bytes().to_vec()),
            Value::Int(i) => (ValueType::QWORD, i.to_le_bytes().to_vec()),
            Value::Str(s) => {
                let mut data = s.as_bytes().to_vec();
                data.push(0);
                (ValueType::SZ, data)
            }
            Value::List(items) => {
                let mut data = Vec::new();
                for item in items {
                    data.extend_from_slice(item.as_bytes());
                    data.push(0);
                }
                data.push(0);
                (ValueType::MULTI_SZ, data)
            }
            Value::Bytes(b) => (ValueType::BINARY, b.clone()),
        }
    }

    fn decode(ty: ValueType, data: &[u8]) -> Option<Value> {
        let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).ok();
        match ty {
            ValueType::DWORD if data.len() == 4 => Some(Value::Int(i64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])))),
            ValueType::QWORD if data.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(data);
                Some(Value::Int(i64::from_le_bytes(b)))
            }
            ValueType::SZ | ValueType::EXPAND_SZ => {
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                text(&data[..end]).map(Value::Str)
            }
            ValueType::MULTI_SZ => Some(Value::List(data.split(|&b| b == 0).filter(|s| !s.is_empty()).filter_map(text).collect())),
            _ => Some(Value::Bytes(data.to_vec())),
        }
    }
}

/// A key read whole: its name, its values in the order the registry gives
/// them, and its subkeys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    pub name: String,
    pub values: Vec<(String, Value)>,
    pub children: Vec<Tree>,
}

impl Tree {
    pub fn new(name: &str) -> Tree {
        Tree { name: name.to_string(), values: Vec::new(), children: Vec::new() }
    }

    /// The value `name`, matched without regard to case, as the registry
    /// matches names.
    pub fn value(&self, name: &str) -> Option<&Value> {
        self.values.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }

    pub fn child(&self, name: &str) -> Option<&Tree> {
        self.children.iter().find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// The key at `path` below this one, `/`-separated.
    pub fn at(&self, path: &str) -> Option<&Tree> {
        let mut here = self;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            here = here.child(part)?;
        }
        Some(here)
    }
}

/// How deep a tree is read. PNP refuses rules nested deeper than 12, and a
/// registry has no cycles; this only bounds a pathological tree.
const MAX_DEPTH: usize = 16;

const READ: KeyAccess = KeyAccess::QUERY_VALUE.union(KeyAccess::ENUMERATE_SUB_KEYS);

fn read_key(key: &Key, name: &str, depth: usize) -> Result<Tree, String> {
    let mut tree = Tree::new(name);
    for record in key.query_values_batch(None).map_err(|e| e.to_string())? {
        let Ok(value_name) = String::from_utf8(record.name.clone()) else { continue };
        if let Some(value) = Value::decode(record.ty, &record.data) {
            tree.values.push((value_name, value));
        }
    }
    if depth < MAX_DEPTH {
        for subkey in key.subkeys(None) {
            let subkey = subkey.map_err(|e| e.to_string())?;
            let Ok(child_name) = String::from_utf8(subkey.name) else { continue };
            match Key::open(Some(key), &child_name, READ, OpenFlags::empty()) {
                Ok(child) => tree.children.push(read_key(&child, &child_name, depth + 1)?),
                // A key this person may not read is left out, not fatal.
                Err(e) if e.raw_os_error() == Some(libc_eacces()) => {}
                Err(e) => return Err(format!("{child_name}: {e}")),
            }
        }
    }
    Ok(tree)
}

fn libc_eacces() -> i32 {
    13
}

fn absent(e: &peios::Error) -> bool {
    e.raw_os_error() == Some(2)
}

/// Reads the key at `path` whole, or `None` when there is no such key.
pub fn read(path: &str) -> Result<Option<Tree>, String> {
    let name = path.rsplit('\\').next().unwrap_or(path);
    match Key::open(None, path, READ, OpenFlags::empty()) {
        Ok(key) => read_key(&key, name, 0).map(Some),
        Err(e) if absent(&e) => Ok(None),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

/// Reads one value, or `None` when there is no such key or value.
pub fn value(path: &str, name: &str) -> Option<Value> {
    let key = Key::open(None, path, KeyAccess::QUERY_VALUE, OpenFlags::empty()).ok()?;
    let found = key.query_value(name.as_bytes(), None).ok()?;
    Value::decode(found.ty, &found.data)
}

/// Whether the person may change the key at `path`: whether it opens for
/// setting values and making subkeys. The registry's own answer, asked
/// rather than guessed.
pub fn may_change(path: &str) -> bool {
    Key::open(None, path, KeyAccess::SET_VALUE | KeyAccess::CREATE_SUB_KEY, OpenFlags::empty()).is_ok()
}

/// One change to a key, in a [`Batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Make the key if it isn't there and set these values. With
    /// `replace`, every other value on it goes.
    Put { path: String, values: Vec<(String, Value)>, replace: bool },
    /// Remove these values from the key.
    Unset { path: String, names: Vec<String> },
    /// Remove the key and everything under it.
    Delete { path: String },
    /// Put the key back exactly as `tree` has it, or remove it when `tree`
    /// is `None`: what undoing a change writes.
    Restore { path: String, tree: Option<Tree> },
}

/// Changes made together: all of them, or none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch(pub Vec<Edit>);

const WRITE: KeyAccess = KeyAccess::QUERY_VALUE
    .union(KeyAccess::SET_VALUE)
    .union(KeyAccess::CREATE_SUB_KEY)
    .union(KeyAccess::ENUMERATE_SUB_KEYS);

/// Opens the key at an absolute `path` within `txn`, making it and what
/// leads to it, from `hive`, the key its first part names, opened before
/// the transaction began.
fn create(hive: &Key, path: &str, txn: &Transaction) -> Result<Key, String> {
    let mut parts = path.split('\\').filter(|p| !p.is_empty()).skip(1);
    let Some(first) = parts.next() else { return Err(format!("{path}: not a key under a hive")) };
    let (mut key, _) = Key::create(Some(hive), first, WRITE, CreateFlags::empty(), None, Some(txn)).map_err(|e| format!("{path}: {e}"))?;
    for part in parts {
        let (child, _) = Key::create(Some(&key), part, WRITE, CreateFlags::empty(), None, Some(txn)).map_err(|e| format!("{path}: {e}"))?;
        key = child;
    }
    Ok(key)
}

/// Opens the key at `path` and every key under it, each after the keys
/// under it, so that deleting them in order deletes children first; nothing
/// when there is no such key.
fn gather(path: &str) -> Result<Vec<Key>, String> {
    fn under(key: Key, out: &mut Vec<Key>) -> Result<(), String> {
        let names: Vec<String> = key.subkeys(None).filter_map(|s| s.ok()).filter_map(|s| String::from_utf8(s.name).ok()).collect();
        for name in names {
            let child = Key::open(Some(&key), &name, KeyAccess::DELETE | KeyAccess::ENUMERATE_SUB_KEYS, OpenFlags::OPEN_LINK).map_err(|e| format!("{name}: {e}"))?;
            under(child, out)?;
        }
        out.push(key);
        Ok(())
    }
    match Key::open(None, path, KeyAccess::DELETE | KeyAccess::ENUMERATE_SUB_KEYS, OpenFlags::empty()) {
        Ok(key) => {
            let mut out = Vec::new();
            under(key, &mut out).map_err(|e| format!("{path}: {e}"))?;
            Ok(out)
        }
        Err(e) if absent(&e) => Ok(Vec::new()),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

fn put(key: &Key, values: &[(String, Value)], replace: bool, txn: &Transaction) -> Result<(), String> {
    if replace {
        for record in key.query_values_batch(Some(txn)).map_err(|e| e.to_string())? {
            if !values.iter().any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(&record.name)) {
                key.delete_value(&record.name, None, Some(txn)).map_err(|e| e.to_string())?;
            }
        }
    }
    for (name, value) in values {
        let (ty, data) = value.encode();
        key.set_value(name.as_bytes(), ty, &data).in_txn(txn).call().map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

fn restore(hive: &Key, path: &str, tree: &Tree, txn: &Transaction) -> Result<(), String> {
    let key = create(hive, path, txn)?;
    put(&key, &tree.values, true, txn)?;
    for child in &tree.children {
        restore(hive, &format!("{path}\\{}", child.name), child, txn)?;
    }
    Ok(())
}

impl Batch {
    pub fn push(&mut self, edit: Edit) {
        self.0.push(edit);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Makes every change, as one transaction.
    ///
    /// loregd holds back an open while a transaction that has written is
    /// open (PEI-1241), so every key is opened before the first write: the
    /// hive each path starts from, and every key a delete removes. The rest
    /// are reached by creating them within the transaction, which opens a
    /// key that is there.
    pub fn commit(&self) -> Result<(), String> {
        let mut hives: Vec<(String, Key)> = Vec::new();
        let mut doomed: Vec<Vec<Key>> = Vec::new();
        for edit in &self.0 {
            let path = match edit {
                Edit::Put { path, .. } | Edit::Unset { path, .. } | Edit::Delete { path } | Edit::Restore { path, .. } => path,
            };
            let hive = path.split('\\').next().unwrap_or_default().to_string();
            if !hives.iter().any(|(h, _)| *h == hive) {
                let key = Key::open(None, &hive, WRITE, OpenFlags::empty()).map_err(|e| format!("{hive}: {e}"))?;
                hives.push((hive, key));
            }
            doomed.push(match edit {
                Edit::Delete { path } | Edit::Restore { path, .. } => gather(path)?,
                _ => Vec::new(),
            });
        }
        let hive = |path: &str| -> &Key {
            let name = path.split('\\').next().unwrap_or_default();
            &hives.iter().find(|(h, _)| h == name).expect("every hive is opened").1
        };
        let txn = Transaction::begin().map_err(|e| format!("A change couldn't be started: {e}"))?;
        for (edit, doomed) in self.0.iter().zip(&doomed) {
            for key in doomed {
                key.delete_key(None, Some(&txn)).map_err(|e| format!("A key couldn't be removed: {e}"))?;
            }
            match edit {
                Edit::Put { path, values, replace } => {
                    let key = create(hive(path), path, &txn)?;
                    put(&key, values, *replace, &txn)?;
                }
                Edit::Unset { path, names } => {
                    let key = create(hive(path), path, &txn)?;
                    for name in names {
                        match key.delete_value(name.as_bytes(), None, Some(&txn)) {
                            Ok(()) => {}
                            Err(e) if absent(&e) => {}
                            Err(e) => return Err(format!("{name}: {e}")),
                        }
                    }
                }
                Edit::Delete { .. } => {}
                Edit::Restore { path, tree } => {
                    if let Some(tree) = tree {
                        restore(hive(path), path, tree, &txn)?;
                    }
                }
            }
        }
        txn.commit().map_err(|e| format!("The change couldn't be made: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_survive_their_encoding() {
        for value in [Value::Int(22), Value::Int(-5), Value::Int(1 << 40), Value::Str("in".into()), Value::List(vec!["8080".into(), "8081".into()]), Value::Bytes(vec![1, 2, 3])] {
            let (ty, data) = value.encode();
            assert_eq!(Value::decode(ty, &data), Some(value));
        }
    }

    #[test]
    fn a_path_finds_a_subkey_whatever_its_case() {
        let mut root = Tree::new("Flow");
        let mut ssh = Tree::new("ssh");
        ssh.children.push(Tree::new("too-fast"));
        root.children.push(ssh);
        assert_eq!(root.at("SSH/Too-Fast").map(|t| t.name.as_str()), Some("too-fast"));
        assert!(root.at("ssh/none").is_none());
    }
}
