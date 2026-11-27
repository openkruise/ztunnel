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

use std::sync::Arc;

use super::ProxyState;
use super::workload::{
    GatewayAddress, InboundProtocol, NamespacedHostname, Workload, gatewayaddress::Destination,
    network_addr,
};
use crate::config::{Config, GatewayEndpoint, LocalConfig};
use crate::extensions::extensions::{EgressPolicies, EgressPolicy, EgressPolicyAction};
use crate::identity::Identity;
use crate::sandbox::discovery::Sandbox;
use crate::strng::{self, Strng};

/// Project the validated bootstrap configuration into the state consumed by the proxy.
/// No xDS resources or background discovery tasks are needed for this state.
pub(super) fn build(config: &Config, local: &LocalConfig) -> ProxyState {
    let mut state = ProxyState::new(config.local_node.as_ref().map(strng::new));
    let mut source = workload(local.workload_id.clone(), &local.identity);
    source.workload_ips.push(local.workload_ip);
    source.node = config
        .local_node
        .as_ref()
        .map(strng::new)
        .unwrap_or_default();
    source.network = strng::new(&config.network);
    source.cluster_id = strng::new(&config.cluster_id);

    let mut gateway = workload(
        format!("{}/egress-gateway", local.workload_id).into(),
        &local.gateway.identity,
    );
    gateway.network = source.network.clone();
    let (destination, hbone_mtls_port) = match &local.gateway.address {
        GatewayEndpoint::Address(address) => {
            gateway.workload_ips.push(address.ip());
            (
                Destination::Address(network_addr(gateway.network.clone(), address.ip())),
                address.port(),
            )
        }
        GatewayEndpoint::Hostname { hostname, port } => {
            gateway.hostname = hostname.clone();
            (
                Destination::Hostname(NamespacedHostname {
                    namespace: gateway.namespace.clone(),
                    hostname: hostname.clone(),
                }),
                *port,
            )
        }
    };
    source.egress_policies = Some(EgressPolicies {
        policies: vec![EgressPolicy {
            namespaces: Default::default(),
            match_cidrs: vec![],
            match_ports: vec![],
            policy: EgressPolicyAction::Gateway,
            gateway: Some(GatewayAddress {
                destination,
                hbone_mtls_port,
            }),
        }],
    });
    if let Some(uid) = &local.sandbox_id {
        state.sandboxes.insert(Sandbox {
            uid: uid.clone(),
            workload_uid: Some(source.uid.clone()),
        });
    }
    state.workloads.insert(Arc::new(source));
    state.workloads.insert(Arc::new(gateway));
    state
}

fn workload(uid: Strng, identity: &Identity) -> Workload {
    Workload {
        name: uid.clone(),
        workload_name: uid.clone(),
        uid,
        namespace: Strng::default(),
        trust_domain: identity.trust_domain(),
        service_account: Strng::default(),
        principal: Some(identity.clone()),
        protocol: InboundProtocol::HBONE,
        workload_ips: vec![],
        waypoint: None,
        network_mode: Default::default(),
        network: Strng::default(),
        workload_type: "local".into(),
        canonical_name: Strng::default(),
        canonical_revision: Strng::default(),
        hostname: Strng::default(),
        node: Strng::default(),
        native_tunnel: false,
        application_tunnel: None,
        status: Default::default(),
        cluster_id: Strng::default(),
        locality: Default::default(),
        services: vec![],
        capacity: 1,
        encoded_labels: None,
        egress_policies: None,
        // The local tunnel delegates policy enforcement to its configured gateway.
        traffic_policy_refs: Some(vec![]),
    }
}
