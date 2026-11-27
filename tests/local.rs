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

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Empty;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tonic::{Request, Response, Status};
use tower::ServiceExt;
use ztunnel::config::{Config, DiscoveryConfig, LocalConfig, LocalGateway, RootCert};
use ztunnel::identity::{AuthSource, SecretManager};
use ztunnel::test_helpers::app::{DestinationAddr, TestApp, with_app};
use ztunnel::test_helpers::dns::{n, run_dns};
use ztunnel::test_helpers::{helpers, test_config};
use ztunnel::tls;
use ztunnel::xds::istio::ca::istio_certificate_service_server::{
    IstioCertificateService, IstioCertificateServiceServer,
};
use ztunnel::xds::istio::ca::{IstioCertificateRequest, IstioCertificateResponse};

const SOURCE: &str = "spiffe://cluster.local/workloads/instance-123";
const GATEWAY: &str = "spiffe://cluster.local/gateways/porter";

fn local_config(gateway: SocketAddr, sandbox: Option<&str>) -> Config {
    let mut config = test_config();
    let local = LocalConfig {
        workload_id: "instance-123".into(),
        workload_ip: "127.0.0.2".parse().unwrap(),
        identity: SOURCE.parse().unwrap(),
        gateway: LocalGateway {
            address: gateway.to_string().parse().unwrap(),
            identity: GATEWAY.parse().unwrap(),
        },
        sandbox_id: sandbox.map(Into::into),
        identity_dir: None,
    };
    config.proxy_workload_information = None;
    config.discovery = DiscoveryConfig::Local(Box::new(local));
    config.local_xds_config = None;
    config.xds_address = None;
    config.dns_proxy = false;
    config
}

struct GatewayRequest {
    destination: String,
    sandbox: Option<String>,
    identity: String,
}

async fn gateway() -> (SocketAddr, mpsc::UnboundedReceiver<GatewayRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let certificate = tls::mock::generate_test_certs(
        &GATEWAY
            .parse::<ztunnel::identity::Identity>()
            .unwrap()
            .into(),
        Duration::ZERO,
        Duration::from_secs(60),
    );
    let acceptor =
        tokio_rustls::TlsAcceptor::from(Arc::new(certificate.server_config(None).unwrap()));
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::debug!(?error, "test gateway TLS handshake rejected");
                        return;
                    }
                };
                let identity = tls::identity_from_connection(stream.get_ref().1)
                    .unwrap()
                    .to_string();
                ztunnel::hyper_util::http2_server()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            assert_eq!(request.method(), hyper::Method::CONNECT);
                            tx.send(GatewayRequest {
                                destination: request.uri().to_string(),
                                sandbox: request
                                    .headers()
                                    .get("x-agentio-sandbox-id")
                                    .map(|v| v.to_str().unwrap().to_string()),
                                identity: identity.clone(),
                            })
                            .unwrap();
                            tokio::spawn(async move {
                                let stream = hyper::upgrade::on(request).await.unwrap();
                                let mut stream = TokioIo::new(stream);
                                let mut buffer = [0u8; 1024];
                                loop {
                                    let read = stream.read(&mut buffer).await.unwrap();
                                    if read == 0 {
                                        break;
                                    }
                                    stream.write_all(&buffer[..read]).await.unwrap();
                                }
                                stream.shutdown().await.unwrap();
                            });
                            async {
                                Ok::<_, Infallible>(hyper::Response::new(Empty::<Bytes>::new()))
                            }
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    (address, rx)
}

#[tokio::test]
async fn local_hbone_preserves_original_destination_sandbox_and_identity() {
    helpers::initialize_telemetry();
    let (gateway, mut requests) = gateway().await;
    let dns = run_dns(std::collections::HashMap::from([(
        n("egress.example."),
        vec![gateway.ip()],
    )]))
    .await
    .unwrap();
    for sandbox in [None, Some("sandbox-123")] {
        let mut config = local_config(gateway, sandbox);
        if sandbox.is_some() {
            let DiscoveryConfig::Local(local) = &mut config.discovery else {
                unreachable!();
            };
            local.gateway.address = format!("egress.example:{}", gateway.port())
                .parse()
                .unwrap();
            config.local_node = Some("standalone-host".into());
            config.network = "external-network".into();
            config.dns_resolver_cfg = dns.resolver_config();
        }
        with_app(config, async |app: TestApp| {
            for target in ["203.0.113.7:443", "[2001:db8::7]:8443"] {
                let mut stream = timeout(
                    Duration::from_secs(5),
                    app.socks5_connect(
                        DestinationAddr::Ip(target.parse().unwrap()),
                        "127.0.0.1".parse().unwrap(),
                    ),
                )
                .await
                .unwrap();
                stream.write_all(b"through-gateway").await.unwrap();
                let mut received = [0u8; 15];
                timeout(Duration::from_secs(5), stream.read_exact(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&received, b"through-gateway");
                drop(stream);
            }
        })
        .await;
        for target in ["203.0.113.7:443", "[2001:db8::7]:8443"] {
            let request = requests.recv().await.unwrap();
            assert_eq!(request.destination, target);
            assert_eq!(request.sandbox.as_deref(), sandbox);
            assert_eq!(request.identity, SOURCE);
        }
    }
}

#[tokio::test]
async fn local_gateway_failures_do_not_fall_back_to_direct_connections() {
    helpers::initialize_telemetry();
    for wrong_identity in [false, true] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (gateway, _requests) = gateway().await;
        let mut config = local_config(gateway, Some("sandbox-123"));
        let DiscoveryConfig::Local(local) = &mut config.discovery else {
            unreachable!();
        };
        if wrong_identity {
            local.gateway.identity = "spiffe://cluster.local/ns/gateway/sa/wrong"
                .parse()
                .unwrap();
        } else {
            let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
            local.gateway.address = unavailable
                .local_addr()
                .unwrap()
                .to_string()
                .parse()
                .unwrap();
            drop(unavailable);
        }
        with_app(config, async |app: TestApp| {
            let mut stream = app
                .socks5_connect(
                    DestinationAddr::Ip(target.local_addr().unwrap()),
                    "127.0.0.1".parse().unwrap(),
                )
                .await;
            let result = timeout(Duration::from_secs(5), stream.read(&mut [0u8; 1]))
                .await
                .expect("failed gateway closes downstream");
            assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
            assert!(
                timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err()
            );
        })
        .await;
    }
}

#[derive(Clone)]
struct Authority {
    requests: mpsc::UnboundedSender<String>,
    reject: bool,
    issuance_gate: Option<Arc<tokio::sync::Notify>>,
}

#[tonic::async_trait]
impl IstioCertificateService for Authority {
    async fn create_certificate(
        &self,
        request: Request<IstioCertificateRequest>,
    ) -> Result<Response<IstioCertificateResponse>, Status> {
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer bootstrap-token"
        );
        let request = request.into_inner();
        assert!(
            request.metadata.is_none(),
            "dedicated CSR must not impersonate another workload"
        );
        assert_eq!(request.validity_duration, 6);
        self.requests.send(request.csr.clone()).unwrap();
        if self.reject {
            return Err(Status::permission_denied("bootstrap identity rejected"));
        }
        if let Some(gate) = &self.issuance_gate {
            gate.notified().await;
        }
        sign_csr(&request.csr, None, false)
    }
}

fn sign_csr(
    csr: &str,
    claims: Option<&ztunnel::identity::WorkloadIdentity>,
    wrong_san: bool,
) -> Result<Response<IstioCertificateResponse>, Status> {
    let mut csr = rcgen::CertificateSigningRequestParams::from_pem(csr).unwrap();
    assert_eq!(
        csr.params.subject_alt_names,
        vec![rcgen::SanType::URI(SOURCE.try_into().unwrap())]
    );
    if wrong_san {
        csr.params.subject_alt_names = vec![rcgen::SanType::URI(GATEWAY.try_into().unwrap())];
    }
    if let Some(claims) = claims {
        csr.params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57874, 5, 1],
            serde_json::to_vec(claims).unwrap(),
        )];
    }
    let now = time::OffsetDateTime::now_utc();
    csr.params.not_before = now - time::Duration::seconds(1);
    csr.params.not_after = now + time::Duration::seconds(6);
    csr.params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    let key =
        rcgen::KeyPair::from_pem(std::str::from_utf8(tls::mock::TEST_ROOT_KEY).unwrap()).unwrap();
    let issuer =
        rcgen::Issuer::from_ca_cert_pem(std::str::from_utf8(tls::mock::TEST_ROOT).unwrap(), key)
            .unwrap();
    let certificate = csr.signed_by(&issuer).unwrap();
    Ok(Response::new(IstioCertificateResponse {
        cert_chain: vec![
            certificate.pem(),
            std::str::from_utf8(tls::mock::TEST_ROOT)
                .unwrap()
                .to_string(),
        ],
    }))
}

async fn control_plane(
    reject: bool,
    issuance_gate: Option<Arc<tokio::sync::Notify>>,
) -> (
    Config,
    mpsc::UnboundedReceiver<String>,
    Arc<Mutex<Vec<String>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let routes = IstioCertificateServiceServer::new(Authority {
        requests: tx,
        reject,
        issuance_gate,
    });
    let certificate = tls::mock::generate_test_certs(
        &address.ip().into(),
        Duration::ZERO,
        Duration::from_secs(60),
    );
    let mut connections = ztunnel::hyper_util::tls_server(
        tls::mock::MockServerCertProvider::new(certificate),
        listener,
    );
    let paths = Arc::new(Mutex::new(Vec::new()));
    let observed = paths.clone();
    tokio::spawn(async move {
        while let Some(connection) = connections.next().await {
            let routes = routes.clone();
            let observed = observed.clone();
            tokio::spawn(async move {
                ztunnel::hyper_util::http2_server()
                    .serve_connection(
                        TokioIo::new(connection),
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            observed
                                .lock()
                                .unwrap()
                                .push(request.uri().path().to_string());
                            routes.clone().oneshot(request)
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
    config.auth = AuthSource::StaticToken("bootstrap-token".into(), "external".into());
    // Even an explicitly populated discovery address must not create ADS in local mode.
    config.xds_address = config.ca_address.clone();
    config.xds_root_cert = config.ca_root_cert.clone();
    (config, rx, paths)
}

#[tokio::test]
async fn local_csr_renews_without_opening_ads() {
    helpers::initialize_telemetry();
    let (gateway, mut forwarded) = gateway().await;
    let (mut config, mut requests, paths) = control_plane(false, None).await;
    let DiscoveryConfig::Local(local) = &mut config.discovery else {
        unreachable!();
    };
    local.gateway.address = gateway.to_string().parse().unwrap();
    let manager = Arc::new(SecretManager::new(Arc::new(config.clone())).await.unwrap());
    let app = ztunnel::app::build_with_cert(Arc::new(config), manager.clone())
        .await
        .unwrap();
    let client = TestApp::from((&app, manager));
    client.ready().await;
    let first = requests.recv().await.unwrap();
    // Use the issued non-Kubernetes certificate on the shared HBONE path.
    let mut stream = client
        .socks5_connect(
            DestinationAddr::Ip("203.0.113.7:443".parse().unwrap()),
            "127.0.0.1".parse().unwrap(),
        )
        .await;
    stream.write_all(b"csr-to-hbone").await.unwrap();
    let mut received = [0u8; 12];
    timeout(Duration::from_secs(5), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"csr-to-hbone");
    assert_eq!(forwarded.recv().await.unwrap().identity, SOURCE);
    drop(stream);
    let renewal = timeout(Duration::from_secs(6), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        first, renewal,
        "renewal generates a new private key and CSR"
    );
    let shutdown = app.shutdown.trigger();
    let (result, ()) = tokio::join!(app.wait_termination(), shutdown.shutdown_now());
    result.unwrap();
    let paths = paths.lock().unwrap();
    assert!(paths.len() >= 2);
    assert!(
        paths
            .iter()
            .all(|path| path == "/istio.v1.auth.IstioCertificateService/CreateCertificate"),
        "{paths:?}"
    );
}

#[tokio::test]
async fn local_rejected_initial_csr_prevents_startup() {
    helpers::initialize_telemetry();
    let (config, mut requests, paths) = control_plane(true, None).await;
    let error = ztunnel::app::build(Arc::new(config))
        .await
        .err()
        .expect("CSR rejection must fail startup");
    assert!(
        format!("{error:#}").contains("bootstrap identity rejected"),
        "{error:#}"
    );
    assert!(requests.recv().await.is_some());
    assert_eq!(paths.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn local_startup_waits_for_the_first_certificate() {
    helpers::initialize_telemetry();
    let gate = Arc::new(tokio::sync::Notify::new());
    let (config, mut requests, _) = control_plane(false, Some(gate.clone())).await;
    let startup = tokio::spawn(ztunnel::app::build(Arc::new(config)));
    timeout(Duration::from_secs(5), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!startup.is_finished(), "startup must wait for CA issuance");
    gate.notify_one();
    let app = timeout(Duration::from_secs(5), startup)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let shutdown = app.shutdown.trigger();
    let (result, ()) = tokio::join!(app.wait_termination(), shutdown.shutdown_now());
    result.unwrap();
}

#[path = "local/standalone.rs"]
mod standalone;
