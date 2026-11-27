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

use std::fmt::{self, Write};
use std::str::FromStr;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};

use super::Error;
use crate::strng::{self, Strng};

/// A SPIFFE identity. The path is opaque to certificate and proxy code.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct Identity {
    uri: Strng,
    trust_domain: Strng,
}

impl Identity {
    /// Construct the legacy Kubernetes ServiceAccount identity at the discovery adapter.
    pub fn from_parts(trust_domain: Strng, namespace: Strng, service_account: Strng) -> Self {
        Self {
            uri: strng::format!("spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"),
            trust_domain,
        }
    }

    pub fn to_strng(&self) -> Strng {
        self.uri.clone()
    }

    pub fn trust_domain(&self) -> Strng {
        self.trust_domain.clone()
    }
}

impl FromStr for Identity {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || Error::Spiffe(value.into());
        let rest = value.strip_prefix("spiffe://").ok_or_else(invalid)?;
        let mut segments = rest.split('/');
        let trust_domain = segments.next().expect("split always has a first element");
        let valid_segment = |s: &str| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        };
        if value.len() > 2048
            || trust_domain.len() > 255
            || !valid_segment(trust_domain)
            || trust_domain.bytes().any(|c| c.is_ascii_uppercase())
            || !segments.all(valid_segment)
        {
            return Err(invalid());
        }
        Ok(Self {
            uri: value.into(),
            trust_domain: trust_domain.into(),
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

impl EncodeLabelValue for Identity {
    fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), fmt::Error> {
        writer.write_str(&self.uri)
    }
}

impl serde::Serialize for Identity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.uri)
    }
}

impl<'de> serde::Deserialize<'de> for Identity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Identity {
    fn default() -> Self {
        Self::from_parts(
            super::DEFAULT_TRUST_DOMAIN.into(),
            "istio-system".into(),
            "ztunnel".into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_preserve_the_full_uri() {
        for uri in [
            "spiffe://agentio.local/workloads/vm-123",
            "spiffe://agentio.local/gateways/egress",
            "spiffe://cluster.local/ns/default/sa/app",
            "spiffe://example.org",
        ] {
            let identity: Identity = uri.parse().unwrap();
            assert_eq!(identity.to_string(), uri);
            assert_eq!(identity.to_strng(), uri);
            assert_eq!(identity.trust_domain(), uri[9..].split('/').next().unwrap());
            let json = serde_json::to_string(&identity).unwrap();
            assert_eq!(serde_json::from_str::<Identity>(&json).unwrap(), identity);
        }
    }

    #[test]
    fn invalid_identities() {
        for uri in [
            "https://example.org/workload",
            "spiffe:///workload",
            "spiffe://EXAMPLE.org/workload",
            "spiffe://example.org:443/workload",
            "spiffe://user@example.org/workload",
            "spiffe://example.org/workload?query",
            "spiffe://example.org/workload#fragment",
            "spiffe://example.org/workload%2Fone",
            "spiffe://example.org//workload",
            "spiffe://example.org/workload/",
            "spiffe://example.org/../workload",
            "spiffe://example.org/./workload",
        ] {
            assert!(uri.parse::<Identity>().is_err(), "{uri}");
        }
        assert!(
            format!("spiffe://{}/workload", "a".repeat(256))
                .parse::<Identity>()
                .is_err()
        );
        assert!(
            format!("spiffe://example.org/{}", "a".repeat(2048))
                .parse::<Identity>()
                .is_err()
        );
    }
}
