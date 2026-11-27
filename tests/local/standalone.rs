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
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use ztunnel::identity::{Identity, WorkloadIdentity};
use ztunnel::sandbox::sandbox::rpc::{
    PrepareSandboxRequest, sandbox_network_client::SandboxNetworkClient,
};
use ztunnel::xds::agentio::sandbox::{
    GetSandboxRequest, GetSandboxResponse, Sandbox,
    sandbox::Attester,
    sandbox_query_service_server::{SandboxQueryService, SandboxQueryServiceServer},
};

#[derive(Clone)]
struct Peer {
    principal: Identity,
    instance: Option<WorkloadIdentity>,
    certificate: rustls::pki_types::CertificateDer<'static>,
}

struct AuthorityState {
    requests: mpsc::UnboundedSender<bool>,
    bootstrap_used: AtomicBool,
    queries: AtomicUsize,
    connections: AtomicUsize,
    query_certificates: Mutex<Vec<rustls::pki_types::CertificateDer<'static>>>,
    response: RwLock<Result<GetSandboxResponse, Status>>,
    wrong_san: bool,
}

fn binding(uid: &str, workload: &str, ttl: Duration) -> GetSandboxResponse {
    GetSandboxResponse {
        sandbox: Some(Sandbox {
            uid: uid.into(),
            attester: Some(Attester {
                workload_uid: workload.into(),
            }),
            extensions: vec![],
        }),
        cache_ttl: Some(ttl.try_into().unwrap()),
    }
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

#[tonic::async_trait]
impl SandboxQueryService for InstanceAuthority {
    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        assert!(!authenticated(&request));
        self.0.query_certificates.lock().unwrap().push(
            request
                .extensions()
                .get::<Peer>()
                .unwrap()
                .certificate
                .clone(),
        );
        assert!(request.get_ref().node_id.starts_with("ztunnel~"));
        self.0.queries.fetch_add(1, Ordering::SeqCst);
        self.0.response.read().unwrap().clone().map(Response::new)
    }
}

async fn control_plane(
    directory: Option<&std::path::Path>,
    wrong_san: bool,
) -> (Config, mpsc::UnboundedReceiver<bool>, Arc<AuthorityState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let state = Arc::new(AuthorityState {
        requests: tx,
        bootstrap_used: AtomicBool::new(false),
        queries: AtomicUsize::new(0),
        connections: AtomicUsize::new(0),
        query_certificates: Mutex::new(vec![]),
        response: RwLock::new(Err(Status::unavailable("Sandbox source unavailable"))),
        wrong_san,
    });
    let authority = InstanceAuthority(state.clone());
    let ca = IstioCertificateServiceServer::new(authority.clone());
    let query = SandboxQueryServiceServer::new(authority);
    let certificate = tls::mock::generate_test_certs(
        &address.ip().into(),
        Duration::ZERO,
        Duration::from_secs(60),
    );
    let mut connections = ztunnel::hyper_util::tls_server(
        tls::mock::MockServerCertProvider::new(certificate).with_optional_client_auth(),
        listener,
    );
    let observed = state.clone();
    tokio::spawn(async move {
        while let Some(connection) = connections.next().await {
            observed.connections.fetch_add(1, Ordering::SeqCst);
            let peer = connection
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .map(|cert| Peer {
                    principal: tls::identity_from_connection(connection.get_ref().1).unwrap(),
                    instance: WorkloadIdentity::from_certificate(cert).unwrap(),
                    certificate: cert.clone(),
                });
            let ca = ca.clone();
            let query = query.clone();
            tokio::spawn(async move {
                ztunnel::hyper_util::http2_server()
                    .serve_connection(
                        TokioIo::new(connection),
                        service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                            if let Some(peer) = &peer {
                                request.extensions_mut().insert(peer.clone());
                            }
                            let ca = ca.clone();
                            let query = query.clone();
                            async move {
                                if request.uri().path().ends_with("/GetSandbox") {
                                    query.oneshot(request).await
                                } else {
                                    ca.oneshot(request).await
                                }
                            }
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    let mut config = local_config("127.0.0.1:15008".parse().unwrap(), None);
    config.fake_ca = false;
    config.secret_ttl = Duration::from_secs(6);
    config.ca_address = Some(format!("https://{address}"));
    config.ca_root_cert = RootCert::Static(tls::mock::TEST_ROOT.into());
    config.auth = AuthSource::StaticToken("bootstrap-token".into(), "agentio".into());
    let DiscoveryConfig::Local(local) = &mut config.discovery else {
        unreachable!()
    };
    local.identity_dir = directory.map(Into::into);
    (config, rx, state)
}

#[tokio::test]
async fn certificate_renewal_and_restart_do_not_need_bootstrap_or_sandbox_source() {
    helpers::initialize_telemetry();
    let directory = tempfile::tempdir().unwrap();
    let (mut config, mut requests, state) = control_plane(Some(directory.path()), false).await;
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
    assert_eq!(state.queries.load(Ordering::SeqCst), 0);
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
    assert_eq!(state.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn local_csr_rejects_an_unexpected_san_without_impersonation() {
    let (config, _requests, _state) = control_plane(None, true).await;
    let manager = SecretManager::new(Arc::new(config)).await.unwrap();
    assert!(matches!(
        manager.fetch_certificate(&SOURCE.parse().unwrap()).await,
        Err(ztunnel::identity::Error::SanError(_))
    ));
}

#[tokio::test]
async fn sandbox_query_reconnects_with_the_renewed_workload_certificate() {
    use ztunnel::sandbox::lookup::{GetSandboxLookup, SandboxLookup};
    let directory = tempfile::tempdir().unwrap();
    let (config, mut requests, state) = control_plane(Some(directory.path()), false).await;
    *state.response.write().unwrap() = Ok(binding(
        "sandbox-123",
        "instance-123",
        Duration::from_secs(60),
    ));
    let config = Arc::new(config);
    let manager = Arc::new(SecretManager::new(config.clone()).await.unwrap());
    let identity = SOURCE.parse().unwrap();
    let first = manager.fetch_certificate(&identity).await.unwrap();
    assert!(requests.recv().await.unwrap());
    let DiscoveryConfig::Local(local) = &config.discovery else {
        unreachable!()
    };
    let lookup =
        GetSandboxLookup::new(config.clone(), local.as_ref().clone(), manager.clone()).unwrap();
    lookup.fetch(&"sandbox-123".into()).await.unwrap();
    assert_eq!(state.query_certificates.lock().unwrap()[0], first.cert.der);
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
    lookup.fetch(&"sandbox-123".into()).await.unwrap();
    assert_eq!(
        state.query_certificates.lock().unwrap()[1],
        renewed.cert.der
    );
}

async fn forward(client: &TestApp) {
    let mut stream = client
        .socks5_connect(
            DestinationAddr::Ip("203.0.113.7:443".parse().unwrap()),
            "127.0.0.1".parse().unwrap(),
        )
        .await;
    stream.write_all(b"binding").await.unwrap();
    let mut buffer = [0; 7];
    timeout(Duration::from_secs(5), stream.read_exact(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer, b"binding");
}

#[tokio::test]
async fn warm_proxy_prepares_a_sandbox_using_mtls_get_and_cached_binding() {
    helpers::initialize_telemetry();
    let identity_directory = tempfile::tempdir().unwrap();
    let registration_directory = tempfile::tempdir().unwrap();
    let (mut config, _requests, state) =
        control_plane(Some(identity_directory.path()), false).await;
    let (gateway, mut forwarded) = gateway().await;
    let DiscoveryConfig::Local(local) = &mut config.discovery else {
        unreachable!()
    };
    local.gateway.address = gateway.to_string().parse().unwrap();
    config.enable_sandbox_manager = true;
    config.sandbox_state_dir = registration_directory.path().into();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let preparation_address = reservation.local_addr().unwrap();
    config.sandbox_prepare_addr = preparation_address;
    drop(reservation);
    let manager = Arc::new(SecretManager::new(Arc::new(config.clone())).await.unwrap());
    let app = ztunnel::app::build_with_cert(Arc::new(config), manager.clone())
        .await
        .unwrap();
    let client = TestApp::from((&app, manager));
    client.ready().await;
    assert_eq!(
        state.queries.load(Ordering::SeqCst),
        0,
        "unassigned startup must not query the Sandbox source"
    );
    forward(&client).await;
    assert!(forwarded.recv().await.unwrap().sandbox.is_none());

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{preparation_address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut preparation = SandboxNetworkClient::new(channel);
    let request = || PrepareSandboxRequest {
        sandbox_id: "sandbox-123".into(),
    };
    assert_eq!(
        preparation
            .prepare_sandbox(request())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(!registration_directory.path().join("sandbox.json").exists());
    *state.response.write().unwrap() = Ok(binding(
        "sandbox-123",
        "wrong-instance",
        Duration::from_secs(60),
    ));
    assert_eq!(
        preparation
            .prepare_sandbox(request())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert!(!registration_directory.path().join("sandbox.json").exists());
    for ttl in [
        None,
        Some(prost_types::Duration {
            seconds: 0,
            nanos: 0,
        }),
        Some(prost_types::Duration {
            seconds: -1,
            nanos: 0,
        }),
    ] {
        let mut response = binding("sandbox-123", "instance-123", Duration::from_secs(60));
        response.cache_ttl = ttl;
        *state.response.write().unwrap() = Ok(response);
        assert_eq!(
            preparation
                .prepare_sandbox(request())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }
    *state.response.write().unwrap() = Ok(binding(
        "other-sandbox",
        "instance-123",
        Duration::from_secs(60),
    ));
    assert_eq!(
        preparation
            .prepare_sandbox(request())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    *state.response.write().unwrap() = Ok(binding(
        "sandbox-123",
        "instance-123",
        Duration::from_secs(60),
    ));
    preparation.prepare_sandbox(request()).await.unwrap();
    assert!(registration_directory.path().join("sandbox.json").exists());
    let queries = state.queries.load(Ordering::SeqCst);
    for _ in 0..3 {
        forward(&client).await;
        assert_eq!(
            forwarded.recv().await.unwrap().sandbox.as_deref(),
            Some("sandbox-123")
        );
    }
    assert_eq!(
        state.queries.load(Ordering::SeqCst),
        queries,
        "connections must not perform GetSandbox calls"
    );
    assert!(
        state.connections.load(Ordering::SeqCst) < queries,
        "Get requests must reuse TLS connections"
    );
    *state.response.write().unwrap() = Ok(binding(
        "sandbox-123",
        "instance-123",
        Duration::from_secs(1),
    ));
    preparation.prepare_sandbox(request()).await.unwrap();

    *state.response.write().unwrap() = Err(Status::unavailable("Sandbox source unavailable"));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(state.queries.load(Ordering::SeqCst) > queries + 1);
    let mut stream = client
        .socks5_connect(
            DestinationAddr::Ip("203.0.113.7:443".parse().unwrap()),
            "127.0.0.1".parse().unwrap(),
        )
        .await;
    let result = timeout(Duration::from_secs(5), stream.read(&mut [0]))
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "expired binding must close a new connection"
    );
    assert!(forwarded.try_recv().is_err());
    let shutdown = app.shutdown.trigger();
    let (result, ()) = tokio::join!(app.wait_termination(), shutdown.shutdown_now());
    result.unwrap();
}
