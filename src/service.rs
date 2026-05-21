use crate::crypto;
use crate::generated::umbral_sidecar_server::{UmbralSidecar};
use crate::generated::*;
use crate::store::KFragStore;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use umbral_pre::{
    generate_kfrags, reencrypt, SecretKey, Signer,
};

pub struct UmbralSidecarService {
    store: Arc<KFragStore>,
}

impl UmbralSidecarService {
    pub fn new() -> Self {
        Self {
            store: Arc::new(KFragStore::new()),
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
    async fn generate_key_pair(
        &self,
        _request: Request<GenerateKeyPairRequest>,
    ) -> Result<Response<GenerateKeyPairResponse>, Status> {
        let sk = SecretKey::random();
        let pk = sk.public_key();

        Ok(Response::new(GenerateKeyPairResponse {
            secret_key: sk.to_be_bytes().as_secret().to_vec(),
            public_key: crypto::serialize_public_key(&pk),
        }))
    }

    async fn generate_k_frags(
        &self,
        request: Request<GenerateKFragsRequest>,
    ) -> Result<Response<GenerateKFragsResponse>, Status> {
        let req = request.into_inner();

        let delegating_sk =
            crypto::deserialize_secret_key(&req.delegating_sk).map_err(Status::invalid_argument)?;
        let receiving_pk =
            crypto::deserialize_public_key(&req.receiving_pk).map_err(Status::invalid_argument)?;
        let signer_sk =
            crypto::deserialize_secret_key(&req.signer_sk).map_err(Status::invalid_argument)?;

        let signer = Signer::new(signer_sk);

        let kfrags = generate_kfrags(
            &delegating_sk,
            &receiving_pk,
            &signer,
            1,
            1,
            true,
            true,
        );

        if let Some(vkfrag) = kfrags.into_vec().first() {
            let vkfrag_for_store = vkfrag.clone();
            let vkfrag_for_response = vkfrag.clone();
            let kfrag_bytes = crypto::serialize_key_frag(&vkfrag_for_store.unverify());
            self.store.insert(&req.org_id, req.epoch_id, &req.receiving_pk, &kfrag_bytes);

            Ok(Response::new(GenerateKFragsResponse {
                kfrag: crypto::serialize_key_frag(&vkfrag_for_response.unverify()),
            }))
        } else {
            Err(Status::internal("generate_kfrags returned no kfrags"))
        }
    }

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
