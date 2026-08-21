use crate::crypto;
use crate::generated::umbral_sidecar_server::{UmbralSidecar};
use crate::generated::*;
use crate::store::KFragStore;
use std::sync::Arc;
use tracing::{error, info, warn};
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
        let member_pk_fp = crypto::fingerprint(&req.member_pk);
        let capsule_fp = crypto::fingerprint(&req.capsule);

        info!(
            op = "re_encrypt",
            org = %req.org_id,
            member_pk_fp = %member_pk_fp,
            capsule_fp = %capsule_fp,
            "re_encrypt entry"
        );

        let kfrag_bytes = match self.store.get(&req.org_id, &req.member_pk) {
            Some(kfrag_bytes) => kfrag_bytes,
            None => {
                warn!(
                    op = "re_encrypt",
                    org = %req.org_id,
                    member_pk_fp = %member_pk_fp,
                    status = "err",
                    reason = "kfrag_not_found",
                    "re_encrypt missing kfrag"
                );
                return Err(Status::not_found(
                    "No kfrag found for specified org/member",
                ));
            }
        };

        let kfrag = crypto::deserialize_key_frag(&kfrag_bytes).map_err(|e| {
            error!(
                op = "re_encrypt",
                org = %req.org_id,
                member_pk_fp = %member_pk_fp,
                status = "err",
                err = %e,
                "re_encrypt invalid kfrag"
            );
            Status::invalid_argument(e.to_string())
        })?;
        let verified_kfrag = kfrag.skip_verification();

        let capsule = crypto::deserialize_capsule(&req.capsule).map_err(|e| {
            error!(
                op = "re_encrypt",
                org = %req.org_id,
                member_pk_fp = %member_pk_fp,
                capsule_fp = %capsule_fp,
                status = "err",
                err = %e,
                "re_encrypt invalid capsule"
            );
            Status::invalid_argument(e.to_string())
        })?;

        let vcfrag = reencrypt(&capsule, verified_kfrag);
        let cfrag_bytes = crypto::serialize_verified_capsule_frag(&vcfrag);

        info!(
            op = "re_encrypt",
            org = %req.org_id,
            status = "ok",
            cfrag_fp = %crypto::fingerprint(&cfrag_bytes),
            cfrag_len = cfrag_bytes.len(),
            "re_encrypt ok"
        );

        Ok(Response::new(ReEncryptResponse {
            cfrag: cfrag_bytes,
        }))
    }

    async fn store_k_frag(
        &self,
        request: Request<StoreKFragRequest>,
    ) -> Result<Response<StoreKFragResponse>, Status> {
        let req = request.into_inner();

        info!(
            op = "store_k_frag",
            org = %req.org_id,
            member_pk_fp = %crypto::fingerprint(&req.member_pk),
            kfrag_len = req.kfrag.len(),
            "store_k_frag entry"
        );

        self.store.insert(&req.org_id, &req.member_pk, &req.kfrag);

        info!(
            op = "store_k_frag",
            org = %req.org_id,
            status = "ok",
            "store_k_frag ok"
        );

        Ok(Response::new(StoreKFragResponse {}))
    }

    async fn delete_k_frags(
        &self,
        request: Request<DeleteKFragsRequest>,
    ) -> Result<Response<DeleteKFragsResponse>, Status> {
        let req = request.into_inner();

        info!(
            op = "delete_k_frags",
            org = %req.org_id,
            member_pk_fp = %crypto::fingerprint(&req.member_pk),
            "delete_k_frags entry"
        );

        let count = self.store.delete(&req.org_id, &req.member_pk);

        info!(
            op = "delete_k_frags",
            org = %req.org_id,
            status = "ok",
            deleted_count = count,
            "delete_k_frags ok"
        );

        Ok(Response::new(DeleteKFragsResponse {
            deleted_count: count,
        }))
    }

    async fn delete_org_k_frags(
        &self,
        request: Request<DeleteOrgKFragsRequest>,
    ) -> Result<Response<DeleteOrgKFragsResponse>, Status> {
        let req = request.into_inner();

        info!(
            op = "delete_org_k_frags",
            org = %req.org_id,
            "delete_org_k_frags entry"
        );

        let count = self.store.delete_org(&req.org_id);

        info!(
            op = "delete_org_k_frags",
            org = %req.org_id,
            status = "ok",
            deleted_count = count,
            "delete_org_k_frags ok"
        );

        Ok(Response::new(DeleteOrgKFragsResponse {
            deleted_count: count,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let kfrag_count = self.store.len();

        info!(op = "health", status = "ok", kfrag_count = kfrag_count, "health check");

        Ok(Response::new(HealthResponse {
            healthy: true,
            kfrag_count,
            umbral_version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }
}
