// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::{discovery::Sandbox, sandbox::Error};
use crate::config::RootCert;
use crate::identity::{AuthSource, Identity, SecretManager};
use crate::state::{DemandProxyState, WorkloadReference};
use crate::strng::Strng;
use crate::tls::{self, RootCertManager, TlsGrpcChannel};
use crate::xds::agentio::sandbox::{
    GetSandboxRequest, sandbox_query_service_client::SandboxQueryServiceClient,
};

/// Preparation may perform I/O; connection selection only reads an accepted snapshot.
#[async_trait]
pub trait SandboxLookup: Send + Sync {
    async fn fetch(&self, id: &Strng, workload: &WorkloadReference) -> Result<Arc<Sandbox>, Error>;
    fn cached(
        &self,
        id: &Strng,
        workload: &WorkloadReference,
    ) -> Result<Option<Arc<Sandbox>>, Error>;
    /// Push-backed sources need no refresh task.
    fn refresh_after(&self, _id: &Strng) -> Option<Duration> {
        None
    }
}

#[async_trait]
impl SandboxLookup for DemandProxyState {
    async fn fetch(&self, id: &Strng, workload: &WorkloadReference) -> Result<Arc<Sandbox>, Error> {
        let current = || {
            self.read()
                .sandboxes
                .get(id)
                .filter(|s| s.workload_uid.is_some())
        };
        if current().is_none() {
            let mut changes = self.read().policies.subscribe();
            let demand = self.fetch_on_demand(crate::xds::SANDBOX_TYPE, id.clone());
            tokio::pin!(demand);
            let mut responded = false;
            loop {
                if current().is_some() {
                    break;
                }
                tokio::select! {
                    _ = &mut demand, if !responded => responded = true,
                    result = changes.changed() => { result?; }
                }
            }
        }
        self.wait_for_workload(workload, super::sandbox::READY_TIMEOUT)
            .await
            .ok_or(Error::UnknownWorkload)?;
        self.cached(id, workload)?.ok_or(Error::NotReady)
    }

    fn cached(
        &self,
        id: &Strng,
        workload: &WorkloadReference,
    ) -> Result<Option<Arc<Sandbox>>, Error> {
        let state = self.read();
        let workload = state
            .workloads
            .find_by_reference(workload)
            .ok_or(Error::NotReady)?;
        state
            .sandboxes
            .get_for_workload(id, &workload.uid)
            .map_err(|_| Error::WorkloadMismatch)
    }
}

struct CachedSandbox {
    sandbox: Option<Arc<Sandbox>>,
    expires: Instant,
    refresh: Instant,
}

type QueryClient = SandboxQueryServiceClient<TlsGrpcChannel>;

pub struct SandboxQueryConfig {
    pub address: String,
    pub root_cert: RootCert,
    pub alt_hostname: Option<String>,
    pub watch_root_cert: bool,
    pub identity: Identity,
    pub node_id: String,
}

/// Queries agentiod using the workload certificate; no platform credentials or ADS stream.
pub struct GetSandboxLookup {
    config: SandboxQueryConfig,
    certificates: Arc<SecretManager>,
    roots: Option<Arc<RootCertManager>>,
    client: Mutex<Option<(Arc<tls::WorkloadCertificate>, QueryClient)>>,
    cache: RwLock<HashMap<Strng, CachedSandbox>>,
}

impl GetSandboxLookup {
    pub fn new(
        config: SandboxQueryConfig,
        certificates: Arc<SecretManager>,
    ) -> Result<Self, crate::identity::Error> {
        let roots = (config.watch_root_cert && matches!(config.root_cert, RootCert::File(_)))
            .then(|| RootCertManager::new(config.root_cert.clone()))
            .transpose()?;
        Ok(Self {
            config,
            certificates,
            roots,
            client: Mutex::new(None),
            cache: RwLock::new(HashMap::new()),
        })
    }

    async fn client(&self) -> Result<QueryClient, Error> {
        let certificate = self
            .certificates
            .fetch_certificate(&self.config.identity)
            .await?;
        let mut cached = self.client.lock().await;
        let dirty = self.roots.as_ref().is_some_and(|r| r.take_dirty());
        if !dirty
            && let Some((current, client)) = &*cached
            && Arc::ptr_eq(current, &certificate)
        {
            return Ok(client.clone());
        }
        let result = async {
            let mut config = tls::control_plane_client_config(
                &self.config.root_cert,
                self.config.alt_hostname.clone(),
            )
            .await?;
            config.client_auth_cert_resolver = certificate.client_cert_resolver()?;
            let channel =
                tls::grpc_connector(self.config.address.clone(), AuthSource::None, config)?;
            Ok::<_, tls::Error>(QueryClient::new(channel))
        }
        .await;
        let client = match result {
            Ok(client) => client,
            Err(error) => {
                if let Some(roots) = &self.roots {
                    roots.mark_dirty();
                }
                return Err(crate::identity::Error::from(error).into());
            }
        };
        *cached = Some((certificate, client.clone()));
        Ok(client)
    }
}

#[async_trait]
impl SandboxLookup for GetSandboxLookup {
    async fn fetch(&self, id: &Strng, workload: &WorkloadReference) -> Result<Arc<Sandbox>, Error> {
        let mut request = tonic::Request::new(GetSandboxRequest {
            name: id.to_string(),
            node_id: self.config.node_id.clone(),
            node_metadata: None,
        });
        request.set_timeout(super::sandbox::READY_TIMEOUT);
        let response = self
            .client()
            .await?
            .get_sandbox(request)
            .await
            .map_err(Box::new)?
            .into_inner();
        let ttl: Duration = response
            .cache_ttl
            .ok_or_else(|| Error::LookupUnavailable("GetSandbox response has no cache TTL".into()))?
            .try_into()
            .map_err(|_| Error::LookupUnavailable("invalid Sandbox cache TTL".into()))?;
        // Forwarding never awaits a lookup, so this adapter requires a cacheable response.
        if ttl.is_zero() {
            return Err(Error::LookupUnavailable(
                "Sandbox preparation requires a positive cache TTL".into(),
            ));
        }
        let sandbox = response
            .sandbox
            .map(Sandbox::try_from)
            .transpose()
            .map_err(Error::InvalidIdentity)?
            .map(Arc::new);
        if sandbox.as_ref().is_some_and(|s| s.uid != *id) {
            return Err(Error::LookupUnavailable(
                "GetSandbox response identity differs from request".into(),
            ));
        }
        let now = Instant::now();
        let expires = now.checked_add(ttl).ok_or_else(|| {
            Error::LookupUnavailable("Sandbox cache TTL exceeds supported duration".into())
        })?;
        self.cache.write().unwrap().insert(
            id.clone(),
            CachedSandbox {
                sandbox,
                expires,
                refresh: now + ttl / 2,
            },
        );
        self.cached(id, workload)?.ok_or(Error::NotReady)
    }

    fn cached(
        &self,
        id: &Strng,
        workload: &WorkloadReference,
    ) -> Result<Option<Arc<Sandbox>>, Error> {
        let WorkloadReference::Uid(uid) = workload else {
            return Err(Error::UnknownWorkload);
        };
        let cache = self.cache.read().unwrap();
        match cache.get(id) {
            Some(entry)
                if entry.expires > Instant::now()
                    && entry
                        .sandbox
                        .as_ref()
                        .is_some_and(|s| s.workload_uid.is_some()) =>
            {
                if entry.sandbox.as_ref().and_then(|s| s.workload_uid.as_ref()) != Some(uid) {
                    return Err(Error::WorkloadMismatch);
                }
                Ok(entry.sandbox.clone())
            }
            _ => Err(Error::LookupUnavailable(
                "Sandbox binding is absent or its cache TTL expired".into(),
            )),
        }
    }

    fn refresh_after(&self, id: &Strng) -> Option<Duration> {
        self.cache
            .read()
            .unwrap()
            .get(id)
            .map(|entry| entry.refresh.saturating_duration_since(Instant::now()))
    }
}
