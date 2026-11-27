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

use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::{Error, Identity, WorkloadIdentity};
use crate::{config::LocalConfig, tls};

pub(super) struct LocalIdentity {
    identity: Identity,
    uid: crate::strng::Strng,
    path: PathBuf,
    pub restored: tokio::sync::Mutex<Option<tls::WorkloadCertificate>>,
    pub resolver: std::sync::RwLock<Option<Arc<dyn rustls::client::ResolvesClientCert>>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Credentials {
    private_key: String,
    cert_chain: Vec<String>,
}

impl LocalIdentity {
    pub async fn new(config: &LocalConfig, directory: PathBuf) -> Result<Self, Error> {
        let local = Self {
            identity: config.identity.clone(),
            uid: config.workload_id.clone(),
            path: directory.join("identity.json"),
            restored: tokio::sync::Mutex::new(None),
            resolver: std::sync::RwLock::new(None),
        };
        let contents = match tokio::fs::read(&local.path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(local),
            Err(error) => return Err(Error::Io(Arc::new(error))),
        };
        let credentials: Credentials = serde_json::from_slice(&contents).map_err(Arc::new)?;
        let (leaf, chain) = credentials
            .cert_chain
            .split_first()
            .ok_or_else(|| Error::EmptyResponse(config.identity.clone()))?;
        let certificate = tls::WorkloadCertificate::new(
            credentials.private_key.as_bytes(),
            leaf.as_bytes(),
            chain.iter().map(|c| c.as_bytes()).collect(),
        )?;
        local.validate(&certificate)?;
        let resolver = certificate.client_cert_resolver()?;
        let now = std::time::SystemTime::now();
        if certificate.cert.expiry.not_before > now {
            return Err(Error::WorkloadIdentity(
                "stored certificate is not yet valid".into(),
            ));
        }
        if certificate.cert.expiry.not_after > now {
            *local.resolver.write().unwrap() = Some(resolver);
            *local.restored.lock().await = Some(certificate);
        } else {
            tracing::info!(
                "stored instance certificate expired; a new bootstrap credential is required"
            );
        }
        Ok(local)
    }

    pub fn validate(&self, certificate: &tls::WorkloadCertificate) -> Result<(), Error> {
        if certificate.identity().as_ref() != Some(&self.identity) {
            return Err(Error::SanError(self.identity.clone()));
        }
        let claims =
            WorkloadIdentity::from_certificate(&certificate.cert.der)?.ok_or_else(|| {
                Error::WorkloadIdentity("instance certificate has no workload identity".into())
            })?;
        if claims.uid != self.uid {
            return Err(Error::WorkloadIdentity(format!(
                "certificate instance {} differs from configured {}",
                claims.uid, self.uid
            )));
        }
        Ok(())
    }

    pub async fn store(&self, certificate: &tls::WorkloadCertificate) -> Result<(), Error> {
        let credentials = Credentials {
            private_key: certificate.private_key_pem(),
            cert_chain: certificate.full_chain_and_roots(),
        };
        let contents = serde_json::to_vec(&credentials).map_err(Arc::new)?;
        let parent = self.path.parent().expect("identity file has a parent");
        tokio::fs::create_dir_all(parent).await.map_err(Arc::new)?;
        let temporary = self.path.with_extension("json.tmp");
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary).await.map_err(Arc::new)?;
        file.write_all(&contents).await.map_err(Arc::new)?;
        file.sync_all().await.map_err(Arc::new)?;
        tokio::fs::rename(&temporary, &self.path)
            .await
            .map_err(Arc::new)?;
        tokio::fs::File::open(parent)
            .await
            .map_err(Arc::new)?
            .sync_all()
            .await
            .map_err(Arc::new)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalGateway;
    use crate::tls::mock::{TestIdentity, generate_test_certs};
    use std::time::Duration;

    fn config() -> LocalConfig {
        LocalConfig {
            workload_id: "instance-123".into(),
            workload_ip: "127.0.0.1".parse().unwrap(),
            identity: "spiffe://example.org/instances/instance-123"
                .parse()
                .unwrap(),
            gateway: LocalGateway {
                address: "127.0.0.1:15008".parse().unwrap(),
                identity: "spiffe://example.org/gateways/egress".parse().unwrap(),
            },
            sandbox_id: None,
            identity_dir: None,
        }
    }

    fn certificate(config: &LocalConfig, uid: &str) -> tls::WorkloadCertificate {
        generate_test_certs(
            &TestIdentity::Workload(
                config.identity.clone(),
                WorkloadIdentity {
                    registry: "local".into(),
                    uid: uid.into(),
                    role: Some("sandbox-attester".into()),
                },
            ),
            Duration::ZERO,
            Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn credentials_round_trip_and_validate_identity() {
        let directory = tempfile::tempdir().unwrap();
        let config = config();
        let local = LocalIdentity::new(&config, directory.path().into())
            .await
            .unwrap();
        assert!(local.restored.lock().await.is_none());
        let cert = certificate(&config, "instance-123");
        local.validate(&cert).unwrap();
        local.store(&cert).await.unwrap();
        let restored = LocalIdentity::new(&config, directory.path().into())
            .await
            .unwrap();
        let restored = restored.restored.lock().await.take().unwrap();
        assert_eq!(restored.cert.der, cert.cert.der);
        assert_eq!(
            restored.private_key.secret_der(),
            cert.private_key.secret_der()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&local.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            local
                .validate(&certificate(&config, "other-instance"))
                .is_err()
        );
        let missing = generate_test_certs(
            &config.identity.clone().into(),
            Duration::ZERO,
            Duration::from_secs(60),
        );
        assert!(local.validate(&missing).is_err());
        let other = LocalConfig {
            identity: "spiffe://example.org/instances/other".parse().unwrap(),
            ..config
        };
        assert!(
            LocalIdentity::new(&other, directory.path().into())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn corrupt_or_mismatched_keys_fail_without_bootstrap_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let config = config();
        let local = LocalIdentity::new(&config, directory.path().into())
            .await
            .unwrap();
        let first = certificate(&config, "instance-123");
        local.store(&first).await.unwrap();
        let mut stored: Credentials =
            serde_json::from_slice(&std::fs::read(&local.path).unwrap()).unwrap();
        stored.private_key = String::from_utf8(
            tls::csr::CsrOptions {
                san: config.identity.to_string(),
            }
            .generate()
            .unwrap()
            .private_key,
        )
        .unwrap();
        std::fs::write(&local.path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(
            LocalIdentity::new(&config, directory.path().into())
                .await
                .is_err()
        );
        std::fs::write(&local.path, "invalid json").unwrap();
        assert!(matches!(
            LocalIdentity::new(&config, directory.path().into()).await,
            Err(Error::Json(_))
        ));
    }

    #[tokio::test]
    async fn expired_credentials_require_bootstrap_again() {
        let directory = tempfile::tempdir().unwrap();
        let config = config();
        let local = LocalIdentity::new(&config, directory.path().into())
            .await
            .unwrap();
        let expired = generate_test_certs(
            &TestIdentity::Workload(
                config.identity.clone(),
                WorkloadIdentity {
                    registry: "local".into(),
                    uid: config.workload_id.clone(),
                    role: None,
                },
            ),
            Duration::ZERO,
            Duration::ZERO,
        );
        local.store(&expired).await.unwrap();
        let restored = LocalIdentity::new(&config, directory.path().into())
            .await
            .unwrap();
        assert!(restored.restored.lock().await.is_none());
        assert!(restored.resolver.read().unwrap().is_none());
        assert!(local.path.is_file());
    }
}
