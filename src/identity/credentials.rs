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
use crate::{strng::Strng, tls};

pub(super) struct WorkloadCredentials {
    identity: Identity,
    uid: Strng,
    path: PathBuf,
    pub restored: tokio::sync::Mutex<Option<tls::WorkloadCertificate>>,
    pub resolver: std::sync::RwLock<Option<Arc<dyn rustls::client::ResolvesClientCert>>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Credentials {
    private_key: String,
    cert_chain: Vec<String>,
}

impl WorkloadCredentials {
    pub async fn new(identity: Identity, uid: Strng, directory: PathBuf) -> Result<Self, Error> {
        let local = Self {
            identity,
            uid,
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
            .ok_or_else(|| Error::EmptyResponse(local.identity.clone()))?;
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
    use crate::tls::mock::{TestIdentity, generate_test_certs};
    use std::time::Duration;

    fn identity() -> Identity {
        "spiffe://example.org/instances/instance-123"
            .parse()
            .unwrap()
    }

    fn certificate(identity: &Identity, uid: &str) -> tls::WorkloadCertificate {
        generate_test_certs(
            &TestIdentity::Workload(
                identity.clone(),
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
        let identity = identity();
        let local = WorkloadCredentials::new(
            identity.clone(),
            "instance-123".into(),
            directory.path().into(),
        )
        .await
        .unwrap();
        assert!(local.restored.lock().await.is_none());
        let cert = certificate(&identity, "instance-123");
        local.validate(&cert).unwrap();
        local.store(&cert).await.unwrap();
        let restored = WorkloadCredentials::new(
            identity.clone(),
            "instance-123".into(),
            directory.path().into(),
        )
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
                .validate(&certificate(&identity, "other-instance"))
                .is_err()
        );
        let missing = generate_test_certs(
            &identity.clone().into(),
            Duration::ZERO,
            Duration::from_secs(60),
        );
        assert!(local.validate(&missing).is_err());
        let other = "spiffe://example.org/instances/other".parse().unwrap();
        assert!(
            WorkloadCredentials::new(other, "instance-123".into(), directory.path().into())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn corrupt_or_mismatched_keys_fail_without_bootstrap_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity();
        let local = WorkloadCredentials::new(
            identity.clone(),
            "instance-123".into(),
            directory.path().into(),
        )
        .await
        .unwrap();
        let first = certificate(&identity, "instance-123");
        local.store(&first).await.unwrap();
        let mut stored: Credentials =
            serde_json::from_slice(&std::fs::read(&local.path).unwrap()).unwrap();
        stored.private_key = String::from_utf8(
            tls::csr::CsrOptions {
                san: identity.to_string(),
            }
            .generate()
            .unwrap()
            .private_key,
        )
        .unwrap();
        std::fs::write(&local.path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(
            WorkloadCredentials::new(
                identity.clone(),
                "instance-123".into(),
                directory.path().into()
            )
            .await
            .is_err()
        );
        std::fs::write(&local.path, "invalid json").unwrap();
        assert!(matches!(
            WorkloadCredentials::new(
                identity.clone(),
                "instance-123".into(),
                directory.path().into()
            )
            .await,
            Err(Error::Json(_))
        ));
    }

    #[tokio::test]
    async fn expired_credentials_require_bootstrap_again() {
        let directory = tempfile::tempdir().unwrap();
        let identity = identity();
        let local = WorkloadCredentials::new(
            identity.clone(),
            "instance-123".into(),
            directory.path().into(),
        )
        .await
        .unwrap();
        let expired = generate_test_certs(
            &TestIdentity::Workload(
                identity.clone(),
                WorkloadIdentity {
                    registry: "local".into(),
                    uid: "instance-123".into(),
                    role: None,
                },
            ),
            Duration::ZERO,
            Duration::ZERO,
        );
        local.store(&expired).await.unwrap();
        let restored = WorkloadCredentials::new(
            identity.clone(),
            "instance-123".into(),
            directory.path().into(),
        )
        .await
        .unwrap();
        assert!(restored.restored.lock().await.is_none());
        assert!(restored.resolver.read().unwrap().is_none());
        assert!(local.path.is_file());
    }
}
