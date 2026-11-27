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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use hyper::http::uri::Authority;

use super::Error;
use crate::identity::Identity;
use crate::strng::Strng;

const DISCOVERY_MODE: &str = "DISCOVERY_MODE";
const WORKLOAD_ID: &str = "WORKLOAD_ID";
const WORKLOAD_IDENTITY: &str = "WORKLOAD_IDENTITY";
const INSTANCE_IP: &str = "INSTANCE_IP";
const SANDBOX_ID: &str = "SANDBOX_ID";
const EGRESS_GATEWAY_ADDRESS: &str = "EGRESS_GATEWAY_ADDRESS";
const EGRESS_GATEWAY_IDENTITY: &str = "EGRESS_GATEWAY_IDENTITY";

#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryConfig {
    #[default]
    Xds,
    Local(Box<LocalConfig>),
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalConfig {
    pub workload_id: Strng,
    pub workload_ip: IpAddr,
    pub identity: Identity,
    pub gateway: LocalGateway,
    pub sandbox_id: Option<Strng>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalGateway {
    pub address: GatewayEndpoint,
    pub identity: Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GatewayEndpoint {
    Address(SocketAddr),
    Hostname { hostname: Strng, port: u16 },
}

impl FromStr for GatewayEndpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let authority = value.parse::<Authority>().map_err(|e| e.to_string())?;
        let port = authority.port_u16().filter(|port| *port != 0);
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let Some(port) = port.filter(|_| !host.is_empty() && !host.contains('@')) else {
            return Err("expected an IP or DNS hostname with a nonzero port".into());
        };
        Ok(match host.parse::<IpAddr>() {
            Ok(ip) => Self::Address(SocketAddr::new(ip, port)),
            Err(_) => Self::Hostname {
                hostname: host.into(),
                port,
            },
        })
    }
}

pub(super) fn parse() -> Result<DiscoveryConfig, Error> {
    match super::parse::<String>(DISCOVERY_MODE)?.as_deref() {
        None | Some("xds") => Ok(DiscoveryConfig::Xds),
        Some("local") => {
            let workload_id: String = required(WORKLOAD_ID)?;
            if workload_id.is_empty() {
                return Err(Error::InvalidState("WORKLOAD_ID must not be empty".into()));
            }
            let sandbox_id = super::parse::<String>(SANDBOX_ID)?;
            if let Some(id) = &sandbox_id {
                crate::sandbox::discovery::validate_id(id)
                    .map_err(|error| Error::InvalidState(error.to_string()))?;
            }
            Ok(DiscoveryConfig::Local(Box::new(LocalConfig {
                workload_id: workload_id.into(),
                workload_ip: super::parse(INSTANCE_IP)?.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                identity: required(WORKLOAD_IDENTITY)?,
                gateway: LocalGateway {
                    address: required(EGRESS_GATEWAY_ADDRESS)?,
                    identity: required(EGRESS_GATEWAY_IDENTITY)?,
                },
                sandbox_id: sandbox_id.map(Into::into),
            })))
        }
        Some(value) => Err(Error::EnvVar(
            DISCOVERY_MODE.into(),
            value.into(),
            "expected xds or local".into(),
        )),
    }
}

fn required<T: FromStr>(name: &str) -> Result<T, Error>
where
    T::Err: ToString,
{
    super::parse(name)?
        .ok_or_else(|| Error::InvalidState(format!("{name} is required in local mode")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, ProxyMode, construct_config};

    #[test]
    fn gateway_endpoints() {
        for address in ["127.0.0.1:15008", "[::1]:15008"] {
            assert_eq!(
                address.parse::<GatewayEndpoint>().unwrap(),
                GatewayEndpoint::Address(address.parse().unwrap())
            );
        }
        assert_eq!(
            "egress.example:15008".parse::<GatewayEndpoint>().unwrap(),
            GatewayEndpoint::Hostname {
                hostname: "egress.example".into(),
                port: 15008,
            }
        );
        for address in [
            "",
            "egress.example",
            "egress.example:0",
            "egress.example:65536",
            "egress.example:abc",
            "https://egress.example:15008",
            ":15008",
        ] {
            assert!(address.parse::<GatewayEndpoint>().is_err(), "{address}");
        }
    }

    #[test]
    fn local_environment() {
        const CASE: &str = "ZTUNNEL_TEST_LOCAL_CONFIG";
        if let Ok(case) = std::env::var(CASE) {
            let result = construct_config(ProxyConfig::default());
            if let Some(expected) = std::env::var_os("ZTUNNEL_EXPECT_CONFIG_ERROR") {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(expected.to_str().unwrap()), "{error}");
                return;
            }
            let config = result.unwrap();
            if case == "default" || case == "xds" {
                assert!(matches!(config.discovery, DiscoveryConfig::Xds));
                assert_eq!(config.proxy_mode, ProxyMode::Shared);
                assert!(config.xds_address.is_some());
                assert!(config.dns_proxy);
            } else {
                let DiscoveryConfig::Local(local) = &config.discovery else {
                    panic!("expected local configuration");
                };
                assert_eq!(config.proxy_mode, ProxyMode::Dedicated);
                assert!(config.proxy_workload_information.is_none());
                assert_eq!(local.workload_id, "vm-123");
                assert_eq!(
                    local.identity.to_string(),
                    "spiffe://agentio.local/workloads/vm-123"
                );
                assert!(config.xds_address.is_none());
                assert!(!config.dns_proxy);
                assert_eq!(
                    config.ca_address.as_deref(),
                    Some("https://ca.example:15012")
                );
                assert_eq!(
                    local.sandbox_id.as_deref(),
                    (case == "sandbox").then_some("sandbox-123")
                );
            }
            return;
        }
        // Follow the existing config tests: isolate environment changes in child processes.
        let cases = [
            ("default", "DISCOVERY_MODE", None, None),
            ("xds", "DISCOVERY_MODE", Some("xds"), None),
            ("local", "DISCOVERY_MODE", Some("local"), None),
            ("sandbox", "SANDBOX_ID", Some("sandbox-123"), None),
            ("pod-metadata", "PROXY_WORKLOAD_INFO", Some("unused"), None),
            (
                "xds-address",
                "XDS_ADDRESS",
                Some("https://unused.example:15012"),
                None,
            ),
            (
                "invalid-mode",
                "DISCOVERY_MODE",
                Some("invalid"),
                Some("DISCOVERY_MODE"),
            ),
            ("missing-id", "WORKLOAD_ID", None, Some("WORKLOAD_ID")),
            ("empty-id", "WORKLOAD_ID", Some(""), Some("WORKLOAD_ID")),
            (
                "missing-identity",
                "WORKLOAD_IDENTITY",
                None,
                Some("WORKLOAD_IDENTITY"),
            ),
            (
                "invalid-identity",
                "WORKLOAD_IDENTITY",
                Some("invalid"),
                Some("WORKLOAD_IDENTITY"),
            ),
            (
                "empty-identity",
                "WORKLOAD_IDENTITY",
                Some("spiffe:///ns/vm/sa/tunnel"),
                Some("WORKLOAD_IDENTITY"),
            ),
            (
                "missing-gateway",
                "EGRESS_GATEWAY_ADDRESS",
                None,
                Some("EGRESS_GATEWAY_ADDRESS"),
            ),
            (
                "invalid-gateway",
                "EGRESS_GATEWAY_ADDRESS",
                Some("egress.example:0"),
                Some("EGRESS_GATEWAY_ADDRESS"),
            ),
            (
                "missing-gateway-identity",
                "EGRESS_GATEWAY_IDENTITY",
                None,
                Some("EGRESS_GATEWAY_IDENTITY"),
            ),
            (
                "invalid-sandbox",
                "SANDBOX_ID",
                Some("*"),
                Some("Sandbox uid"),
            ),
            (
                "invalid-ip",
                "INSTANCE_IP",
                Some("invalid"),
                Some("INSTANCE_IP"),
            ),
            ("missing-ca", "CA_ADDRESS", None, Some("CA_ADDRESS")),
            ("empty-ca", "CA_ADDRESS", Some(""), Some("CA_ADDRESS")),
            (
                "shared",
                "PROXY_MODE",
                Some("shared"),
                Some("PROXY_MODE=dedicated"),
            ),
            (
                "no-proxy",
                "ENABLE_PROXY",
                Some("false"),
                Some("enabled proxy"),
            ),
            ("file", "LOCAL_XDS_PATH", Some("/unused"), Some("LOCAL_XDS")),
            ("inline", "LOCAL_XDS", Some("{}"), Some("LOCAL_XDS")),
            (
                "on-demand",
                "XDS_ON_DEMAND",
                Some("true"),
                Some("XDS_ON_DEMAND"),
            ),
            (
                "manager",
                "ENABLE_SANDBOX_MANAGER",
                Some("true"),
                Some("ENABLE_SANDBOX_MANAGER"),
            ),
        ];
        for (case, name, value, expected_error) in cases {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "config::local::tests::local_environment",
                    "--nocapture",
                ])
                .env_clear()
                .env(CASE, case)
                .env("DISCOVERY_MODE", "local")
                .env("WORKLOAD_ID", "vm-123")
                .env(
                    "WORKLOAD_IDENTITY",
                    "spiffe://agentio.local/workloads/vm-123",
                )
                .env("EGRESS_GATEWAY_ADDRESS", "egress.example:15008")
                .env(
                    "EGRESS_GATEWAY_IDENTITY",
                    "spiffe://agentio.local/gateways/porter",
                )
                .env("CA_ADDRESS", "ca.example:15012");
            if let Some(value) = value {
                command.env(name, value);
            } else {
                command.env_remove(name);
            }
            if let Some(error) = expected_error {
                command.env("ZTUNNEL_EXPECT_CONFIG_ERROR", error);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
