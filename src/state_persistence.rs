use ethereum_types::{H160, H256};
use serde::{Deserialize, Serialize};
use sled::{Config, Db, IVec};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct StorageDiff {
    pub address: H160,
    pub key: H256,
    pub old_value: Option<H256>,
    pub new_value: H256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitMode {
    End,
    Each,
}

impl Default for CommitMode {
    fn default() -> Self {
        CommitMode::End
    }
}

fn encode_key(address: &H160, slot: &H256) -> [u8; 52] {
    let mut buf = [0u8; 52];
    buf[..20].copy_from_slice(address.as_bytes());
    buf[20..].copy_from_slice(slot.as_bytes());
    buf
}

fn key_to_hex(address: &H160, slot: &H256) -> String {
    hex::encode(encode_key(address, slot))
}

#[derive(Default, Serialize, Deserialize)]
struct JsonSnapshot {
    entries: BTreeMap<String, String>,
}

pub struct JsonFallback {
    path: PathBuf,
    snapshot: Mutex<JsonSnapshot>,
}

impl JsonFallback {
    pub fn new(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let snapshot = if path.exists() {
            let mut file = fs::File::open(&path)?;
            let mut data = String::new();
            file.read_to_string(&mut data)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            JsonSnapshot::default()
        };
        Ok(Self {
            path,
            snapshot: Mutex::new(snapshot),
        })
    }

    fn persist(&self) -> anyhow::Result<()> {
        let snapshot = self.snapshot.lock().unwrap();
        let data = serde_json::to_string_pretty(&*snapshot)?;
        fs::write(&self.path, data)?;
        Ok(())
    }

    pub fn get(&self, address: &H160, slot: &H256) -> Option<H256> {
        let snapshot = self.snapshot.lock().unwrap();
        snapshot
            .entries
            .get(&key_to_hex(address, slot))
            .and_then(|hex| match hex::decode(hex) {
                Ok(bytes) if bytes.len() == 32 => Some(H256::from_slice(&bytes)),
                _ => None,
            })
    }

    pub fn insert(&self, address: &H160, slot: &H256, value: H256) -> anyhow::Result<()> {
        let mut snapshot = self.snapshot.lock().unwrap();
        snapshot
            .entries
            .insert(key_to_hex(address, slot), hex::encode(value.as_bytes()));
        self.persist()
    }
}

pub struct StorageState {
    db: Option<Db>,
    fallback: JsonFallback,
}

impl StorageState {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db = Config::new()
            .path(path.as_ref())
            .mode(sled::Mode::HighThroughput)
            .open()
            .ok();
        let json_path = path.as_ref().with_extension("json");
        let fallback = JsonFallback::new(json_path)?;
        Ok(Self { db, fallback })
    }

    pub fn get(&self, address: &H160, slot: &H256) -> Option<H256> {
        if let Some(db) = &self.db {
            let key = encode_key(address, slot);
            if let Ok(Some(value)) = db.get(&key) {
                return Some(H256::from_slice(&value));
            }
        }
        self.fallback.get(address, slot)
    }

    pub fn set(&self, address: &H160, slot: &H256, value: H256) -> anyhow::Result<()> {
        let key = encode_key(address, slot);
        if let Some(db) = &self.db {
            db.insert(&key, value.as_bytes())?;
            db.flush()?;
            return Ok(());
        }
        self.fallback.insert(address, slot, value)
    }
}

pub struct DiffSink {
    storage: Arc<StorageState>,
    pending: HashMap<(H160, H256), StorageDiff>,
    commit_mode: CommitMode,
    diff_dump: Option<PathBuf>,
}

impl DiffSink {
    pub fn new(
        storage: Arc<StorageState>,
        commit_mode: CommitMode,
        diff_dump: Option<PathBuf>,
    ) -> Self {
        Self {
            storage,
            pending: Default::default(),
            commit_mode,
            diff_dump,
        }
    }

    pub fn on_sstore(&mut self, diff: StorageDiff) -> anyhow::Result<()> {
        self.pending.insert((diff.address, diff.key), diff);
        if self.commit_mode == CommitMode::Each {
            self.commit_pending()?;
        }
        if let Some(ref path) = self.diff_dump {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            let content = serde_json::to_string(&diff)?;
            writeln!(file, "{}", content)?;
        }
        Ok(())
    }

    pub fn on_finish(&mut self) -> anyhow::Result<()> {
        self.commit_pending()
    }

    fn commit_pending(&mut self) -> anyhow::Result<()> {
        for diff in self.pending.values() {
            self.storage.set(&diff.address, &diff.key, diff.new_value)?;
        }
        self.pending.clear();
        Ok(())
    }
}

pub struct StorageProvider {
    storage: Arc<StorageState>,
}

impl StorageProvider {
    pub fn new(storage: Arc<StorageState>) -> Self {
        Self { storage }
    }

    pub fn sload(&self, address: &H160, key: &H256) -> H256 {
        self.storage.get(address, key).unwrap_or_else(H256::zero)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persistence_roundtrip() -> anyhow::Result<()> {
        let tmp = tempdir()?;
        let state = Arc::new(StorageState::open(tmp.path())?);
        let mut sink = DiffSink::new(state.clone(), CommitMode::End, None);
        let provider = StorageProvider::new(state.clone());
        let addr = H160::from_low_u64_be(0x1234);
        let key = H256::from_low_u64_be(1);

        let diff = StorageDiff {
            address: addr,
            key,
            old_value: Some(H256::zero()),
            new_value: H256::from_low_u64_be(10),
        };
        sink.on_sstore(diff)?;
        sink.on_finish()?;
        assert_eq!(provider.sload(&addr, &key), diff.new_value);

        let diff2 = StorageDiff {
            address: addr,
            key,
            old_value: Some(diff.new_value),
            new_value: H256::from_low_u64_be(20),
        };
        sink.on_sstore(diff2)?;
        sink.on_finish()?;
        assert_eq!(provider.sload(&addr, &key), diff2.new_value);
        Ok(())
    }
}
