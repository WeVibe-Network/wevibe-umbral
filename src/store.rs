use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::{error, info, warn};

const DEFAULT_KFRAG_STORE_PATH: &str = "/data/kfrags.json";
static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct PersistedKFragStore {
    entries: Vec<PersistedKFragEntry>,
}

#[derive(Serialize, Deserialize)]
struct PersistedKFragEntry {
    org_id: String,
    epoch_id: u64,
    member_pk_hex: String,
    kfrag_hex: String,
}

impl PersistedKFragEntry {
    fn from_runtime_entry(key: &(String, u64, Vec<u8>), value: &[u8]) -> Self {
        Self {
            org_id: key.0.clone(),
            epoch_id: key.1,
            member_pk_hex: hex::encode(&key.2),
            kfrag_hex: hex::encode(value),
        }
    }

    fn to_runtime_entry(&self) -> Result<((String, u64, Vec<u8>), Vec<u8>), String> {
        let member_pk = hex::decode(&self.member_pk_hex)
            .map_err(|err| format!("decode member_pk_hex: {err}"))?;
        let kfrag =
            hex::decode(&self.kfrag_hex).map_err(|err| format!("decode kfrag_hex: {err}"))?;
        Ok(((self.org_id.clone(), self.epoch_id, member_pk), kfrag))
    }
}

#[derive(Clone)]
pub struct KFragStore {
    store: Arc<DashMap<(String, u64, Vec<u8>), Vec<u8>>>,
    path: PathBuf,
    persist_lock: Arc<Mutex<()>>,
}

impl KFragStore {
    pub fn new() -> Self {
        let path = std::env::var("WEVIBE_UMBRAL_KFRAG_STORE")
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KFRAG_STORE_PATH));

        let instance = Self {
            store: Arc::new(DashMap::new()),
            path,
            persist_lock: Arc::new(Mutex::new(())),
        };
        instance.load_from_disk();
        instance
    }

    pub fn insert(&self, org_id: &str, epoch_id: u64, member_pk: &[u8], kfrag: &[u8]) {
        let _persist_guard = self.persist_guard();
        self.store.insert(
            (org_id.to_string(), epoch_id, member_pk.to_vec()),
            kfrag.to_vec(),
        );
        if let Err(err) = self.persist_to_disk() {
            error!(
                "failed to persist kfrag store after insert to {}: {}",
                self.path.display(),
                err
            );
        }
    }

    pub fn get(&self, org_id: &str, epoch_id: u64, member_pk: &[u8]) -> Option<Vec<u8>> {
        self.store
            .get(&(org_id.to_string(), epoch_id, member_pk.to_vec()))
            .map(|v| v.value().clone())
    }

    pub fn delete(&self, org_id: &str, member_pk: &[u8]) -> u32 {
        let _persist_guard = self.persist_guard();
        let mut count = 0;
        let key = member_pk.to_vec();
        self.store.retain(|k, _| {
            if k.0 == org_id && k.2 == key {
                count += 1;
                false
            } else {
                true
            }
        });

        if let Err(err) = self.persist_to_disk() {
            error!(
                "failed to persist kfrag store after delete to {}: {}",
                self.path.display(),
                err
            );
        }
        count
    }

    pub fn delete_org(&self, org_id: &str) -> u32 {
        let _persist_guard = self.persist_guard();
        let mut count = 0;
        self.store.retain(|k, _| {
            if k.0 == org_id {
                count += 1;
                false
            } else {
                true
            }
        });

        if let Err(err) = self.persist_to_disk() {
            error!(
                "failed to persist kfrag store after delete_org to {}: {}",
                self.path.display(),
                err
            );
        }
        count
    }

    pub fn len(&self) -> u64 {
        self.store.len() as u64
    }

    fn persist_guard(&self) -> MutexGuard<'_, ()> {
        match self.persist_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!(
                    "kfrag store persist lock poisoned for {}; continuing with inner lock",
                    self.path.display()
                );
                poisoned.into_inner()
            }
        }
    }

    fn load_from_disk(&self) {
        if !self.path.exists() {
            info!(
                "kfrag store file {} not found; starting with empty in-memory store",
                self.path.display()
            );
            return;
        }

        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(err) => {
                error!(
                    "failed to read kfrag store file {}: {}; starting empty",
                    self.path.display(),
                    err
                );
                return;
            }
        };

        let persisted: PersistedKFragStore = match serde_json::from_slice(&raw) {
            Ok(parsed) => parsed,
            Err(err) => {
                error!(
                    "failed to deserialize kfrag store file {}: {}; starting empty",
                    self.path.display(),
                    err
                );
                return;
            }
        };

        let mut decoded_entries = Vec::with_capacity(persisted.entries.len());
        for (index, entry) in persisted.entries.iter().enumerate() {
            match entry.to_runtime_entry() {
                Ok(runtime_entry) => decoded_entries.push(runtime_entry),
                Err(err) => {
                    error!(
                        "kfrag store file {} is corrupt at entry {}: {}; starting empty",
                        self.path.display(),
                        index,
                        err
                    );
                    return;
                }
            }
        }

        for (key, value) in decoded_entries {
            self.store.insert(key, value);
        }

        info!(
            "loaded {} kfrag entries from {}",
            self.store.len(),
            self.path.display()
        );
    }

    fn snapshot(&self) -> PersistedKFragStore {
        let mut entries: Vec<PersistedKFragEntry> = self
            .store
            .iter()
            .map(|entry| PersistedKFragEntry::from_runtime_entry(entry.key(), entry.value()))
            .collect();

        entries.sort_by(|a, b| {
            a.org_id
                .cmp(&b.org_id)
                .then_with(|| a.epoch_id.cmp(&b.epoch_id))
                .then_with(|| a.member_pk_hex.cmp(&b.member_pk_hex))
        });

        PersistedKFragStore { entries }
    }

    fn store_parent_dir(&self) -> &Path {
        self.path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn persist_to_disk(&self) -> Result<(), String> {
        let snapshot = self.snapshot();
        let payload = serde_json::to_vec_pretty(&snapshot)
            .map_err(|err| format!("serialize snapshot: {err}"))?;

        let parent = self.store_parent_dir();
        fs::create_dir_all(parent)
            .map_err(|err| format!("create store directory {}: {err}", parent.display()))?;

        let file_stem = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("kfrags.json");
        let temp_path = parent.join(format!(
            ".{file_stem}.tmp-{}-{}",
            std::process::id(),
            TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));

        let persist_result = (|| -> Result<(), String> {
            let mut temp_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .map_err(|err| format!("open temp store file {}: {err}", temp_path.display()))?;

            #[cfg(unix)]
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
                format!("set temp store permissions {}: {err}", temp_path.display())
            })?;

            temp_file
                .write_all(&payload)
                .map_err(|err| format!("write temp store file {}: {err}", temp_path.display()))?;

            temp_file
                .sync_all()
                .map_err(|err| format!("fsync temp store file {}: {err}", temp_path.display()))?;

            drop(temp_file);

            fs::rename(&temp_path, &self.path).map_err(|err| {
                format!(
                    "rename temp store {} -> {}: {err}",
                    temp_path.display(),
                    self.path.display()
                )
            })?;

            #[cfg(unix)]
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(|err| {
                format!(
                    "set persisted store permissions {}: {err}",
                    self.path.display()
                )
            })?;

            if let Ok(parent_dir_handle) = File::open(parent) {
                if let Err(err) = parent_dir_handle.sync_all() {
                    warn!(
                        "failed to fsync kfrag store directory {}: {}",
                        parent.display(),
                        err
                    );
                }
            }

            Ok(())
        })();

        if persist_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }

        persist_result
    }
}

impl Default for KFragStore {
    fn default() -> Self {
        Self::new()
    }
}
