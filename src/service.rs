use crate::crypto;
use crate::generated::umbral_sidecar_server::{UmbralSidecar};
use crate::generated::*;
use crate::store::KFragStore;
use std::sync::Arc;
use tracing::{info, warn};
use tonic::{Request, Response, Status};
use umbral_pre::reencrypt;

pub struct UmbralSidecarService {
    store: Arc<KFragStore>,
}

impl UmbralSidecarService {
    pub fn new() -> Self {
        let store = Arc::new(KFragStore::new());
        let startup_count = store.len();

        info!("kfrag store entry count on startup: {}", startup_count);
        if startup_count == 0 {
            warn!(
                "kfrag store empty on startup — recall will fail until provisioned (re-run provision-recall)"
            );
        }

        Self {
            store,
        }
    }
}

impl Default for UmbralSidecarService {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl UmbralSidecar for UmbralSidecarService {
    async fn re_encrypt(
        &self,
        request: Request<ReEncryptRequest>,
    ) -> Result<Response<ReEncryptResponse>, Status> {
        let req = request.into_inner();

        let kfrag_bytes = self
            .store
            .get(&req.org_id, req.epoch_id, &req.member_pk)
            .ok_or_else(|| Status::not_found("No kfrag found for specified org/epoch/member"))?;

        let kfrag = crypto::deserialize_key_frag(&kfrag_bytes).map_err(Status::invalid_argument)?;
        let verified_kfrag = kfrag.skip_verification();

        let capsule = crypto::deserialize_capsule(&req.capsule).map_err(Status::invalid_argument)?;

        let vcfrag = reencrypt(&capsule, verified_kfrag);

        Ok(Response::new(ReEncryptResponse {
            cfrag: crypto::serialize_verified_capsule_frag(&vcfrag),
        }))
    }

    async fn store_k_frag(
        &self,
        request: Request<StoreKFragRequest>,
    ) -> Result<Response<StoreKFragResponse>, Status> {
        let req = request.into_inner();

        self.store
            .insert(&req.org_id, req.epoch_id, &req.member_pk, &req.kfrag);

        Ok(Response::new(StoreKFragResponse {}))
    }

    async fn delete_k_frags(
        &self,
        request: Request<DeleteKFragsRequest>,
    ) -> Result<Response<DeleteKFragsResponse>, Status> {
        let req = request.into_inner();
        let count = self.store.delete(&req.org_id, &req.member_pk);

        Ok(Response::new(DeleteKFragsResponse {
            deleted_count: count,
        }))
    }

    async fn delete_org_k_frags(
        &self,
        request: Request<DeleteOrgKFragsRequest>,
    ) -> Result<Response<DeleteOrgKFragsResponse>, Status> {
        let req = request.into_inner();
        let count = self.store.delete_org(&req.org_id);

        Ok(Response::new(DeleteOrgKFragsResponse {
            deleted_count: count,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            healthy: true,
            kfrag_count: self.store.len(),
            umbral_version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }
}
