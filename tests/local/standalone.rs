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

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use ztunnel::identity::{Identity, WorkloadIdentity};
#[derive(Clone)]
struct Peer {
    principal: Identity,
    instance: Option<WorkloadIdentity>,
}

struct AuthorityState {
    requests: mpsc::UnboundedSender<bool>,
    bootstrap_used: AtomicBool,
    wrong_san: bool,
}

fn authenticated<T>(request: &Request<T>) -> bool {
    if let Some(peer) = request.extensions().get::<Peer>() {
        assert_eq!(peer.principal.to_string(), SOURCE);
        assert_eq!(peer.instance.as_ref().unwrap().uid, "instance-123");
        assert!(request.metadata().get("authorization").is_none());
        false
    } else {
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer bootstrap-token"
        );
        true
    }
}

#[derive(Clone)]
struct InstanceAuthority(Arc<AuthorityState>);

#[tonic::async_trait]
impl IstioCertificateService for InstanceAuthority {
    async fn create_certificate(
        &self,
        request: Request<IstioCertificateRequest>,
    ) -> Result<Response<IstioCertificateResponse>, Status> {
        let bootstrap = authenticated(&request);
        if bootstrap && self.0.bootstrap_used.swap(true, Ordering::SeqCst) {
            return Err(Status::unauthenticated(
                "bootstrap credential already consumed",
            ));
        }
        assert!(request.get_ref().metadata.is_none());
        self.0.requests.send(bootstrap).unwrap();
        sign_csr(
            &request.get_ref().csr,
            Some(&WorkloadIdentity {
                registry: "agentio".into(),
                uid: "instance-123".into(),
                role: Some("sandbox-attester".into()),
            }),
            self.0.wrong_san,
        )
    }
}

async fn control_plane(
    directory: Option<&std::path::Path>,
    wrong_san: bool,
) -> (Config, mpsc::UnboundedReceiver<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let state = Arc::new(AuthorityState {
        requests: tx,
        bootstrap_used: AtomicBool::new(false),
        wrong_san,
    });
    let authority = InstanceAuthority(state.clone());
    let ca = IstioCertificateServiceServer::new(authority);
    let certificate = tls::mock::generate_test_certs(
        &address.ip().into(),
        Duration::ZERO,
        Duration::from_secs(60),
    );
    let mut connections = ztunnel::hyper_util::tls_server(
        tls::mock::MockServerCertProvider::new(certificate).with_optional_client_auth(),
        listener,
    );
    tokio::spawn(async move {
        while let Some(connection) = connections.next().await {
            let peer = connection
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .map(|cert| Peer {
                    principal: tls::identity_from_connection(connection.get_ref().1).unwrap(),
                    instance: WorkloadIdentity::from_certificate(cert).unwrap(),
                });
            let ca = ca.clone();
            tokio::spawn(async move {
                ztunnel::hyper_util::http2_server()
                    .serve_connection(
                        TokioIo::new(connection),
                        service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                            if let Some(peer) = &peer {
                                request.extensions_mut().insert(peer.clone());
                            }
                            let ca = ca.clone();
                            async move { ca.oneshot(request).await }
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    let mut config = local_config("127.0.0.1:15008".parse().unwrap(), "sandbox-123");
    config.fake_ca = false;
    config.secret_ttl = Duration::from_secs(6);
    config.ca_address = Some(format!("https://{address}"));
    config.ca_root_cert = RootCert::Static(tls::mock::TEST_ROOT.into());
    config.auth = AuthSource::StaticToken("bootstrap-token".into(), "agentio".into());
    config.workload_identity_dir = directory.map(Into::into);
    (config, rx)
}

#[tokio::test]
async fn certificate_renewal_and_restart_do_not_need_bootstrap_token() {
    helpers::initialize_telemetry();
    let directory = tempfile::tempdir().unwrap();
    let (mut config, mut requests) = control_plane(Some(directory.path()), false).await;
    let token = directory.path().join("bootstrap.jwt");
    std::fs::write(&token, "bootstrap-token").unwrap();
    config.auth = AuthSource::Token(token.clone(), "agentio".into());
    let manager = SecretManager::new(Arc::new(config.clone())).await.unwrap();
    let identity = SOURCE.parse().unwrap();
    let first = manager.fetch_certificate(&identity).await.unwrap();
    assert!(requests.recv().await.unwrap());
    std::fs::remove_file(&token).unwrap();
    assert!(
        !timeout(Duration::from_secs(6), requests.recv())
            .await
            .unwrap()
            .unwrap()
    );
    ztunnel::test_helpers::assert_eventually(
        Duration::from_secs(1),
        || async { manager.fetch_certificate(&identity).await.unwrap().cert.der != first.cert.der },
        true,
    )
    .await;
    let renewed = manager.fetch_certificate(&identity).await.unwrap();
    assert_ne!(first.cert.der, renewed.cert.der);
    drop(manager);

    config.auth = AuthSource::None;
    let manager = SecretManager::new(Arc::new(config)).await.unwrap();
    let restored = manager.fetch_certificate(&identity).await.unwrap();
    assert_eq!(restored.cert.der, renewed.cert.der);
    assert!(
        requests.try_recv().is_err(),
        "restart should restore the current certificate"
    );
    assert!(
        !timeout(Duration::from_secs(6), requests.recv())
            .await
            .unwrap()
            .unwrap()
    );
}

#[tokio::test]
async fn local_csr_rejects_an_unexpected_san_without_impersonation() {
    let (config, _requests) = control_plane(None, true).await;
    let manager = SecretManager::new(Arc::new(config)).await.unwrap();
    assert!(matches!(
        manager.fetch_certificate(&SOURCE.parse().unwrap()).await,
        Err(ztunnel::identity::Error::SanError(_))
    ));
}
