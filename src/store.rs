use dashmap::DashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct KFragStore {
    store: Arc<DashMap<(String, u64, Vec<u8>), Vec<u8>>>,
}

impl KFragStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, org_id: &str, epoch_id: u64, member_pk: &[u8], kfrag: &[u8]) {
        self.store.insert(
            (org_id.to_string(), epoch_id, member_pk.to_vec()),
            kfrag.to_vec(),
        );
    }

    pub fn get(&self, org_id: &str, epoch_id: u64, member_pk: &[u8]) -> Option<Vec<u8>> {
        self.store
            .get(&(org_id.to_string(), epoch_id, member_pk.to_vec()))
            .map(|v| v.value().clone())
    }

    pub fn delete(&self, org_id: &str, member_pk: &[u8]) -> u32 {
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
        count
    }

    pub fn delete_org(&self, org_id: &str) -> u32 {
        let mut count = 0;
        self.store.retain(|k, _| {
            if k.0 == org_id {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }

    pub fn len(&self) -> u64 {
        self.store.len() as u64
    }
}

impl Default for KFragStore {
    fn default() -> Self {
        Self::new()
    }
}