// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

use crate::extensions::extensions::EgressPolicies;
use crate::strng::Strng;
use crate::xds::kruise::networking::extensions::v1::WorkloadConfigScope;
use std::collections::{HashMap, HashSet};
use tokio::sync::watch;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkloadConfigData {
    pub egress_policies: EgressPolicies,
}

/// A WorkloadConfigStore stores workload configs with a dual-index structure
/// similar to `PolicyStore`. Configs are keyed by their xDS resource name
/// (`namespace/name`) in `by_key`, and a secondary index `by_namespace` maps
/// each namespace to the set of resource keys that belong to it.
///
/// At lookup time, `get_by_namespace` returns all configs for a single
/// namespace. Callers that need both namespace-scoped and global configs
/// should query for the workload namespace and the root namespace separately
/// and merge the results.
#[derive(Debug)]
pub struct WorkloadConfigStore {
    /// Primary store: xDS resource name (`namespace/name`) -> WorkloadConfigData.
    by_key: HashMap<Strng, WorkloadConfigData>,
    /// Secondary index: namespace -> set of xDS resource keys in that namespace.
    by_namespace: HashMap<Strng, HashSet<Strng>>,
    /// Tracks which namespace key each resource was indexed under in `by_namespace`,
    /// so that `remove` can clean up the correct entry.
    key_to_namespace: HashMap<Strng, Strng>,
    notifier: WorkloadConfigStoreNotify,
}

#[derive(Debug)]
struct WorkloadConfigStoreNotify {
    sender: watch::Sender<()>,
}

impl Default for WorkloadConfigStoreNotify {
    fn default() -> Self {
        let (tx, _rx) = watch::channel(());
        WorkloadConfigStoreNotify { sender: tx }
    }
}

impl Default for WorkloadConfigStore {
    fn default() -> Self {
        WorkloadConfigStore {
            by_key: HashMap::new(),
            by_namespace: HashMap::new(),
            key_to_namespace: HashMap::new(),
            notifier: WorkloadConfigStoreNotify::default(),
        }
    }
}

impl WorkloadConfigStore {
    /// Return all extensions whose namespace matches `ns`.
    pub fn get_by_namespace(&self, ns: &Strng) -> Vec<&WorkloadConfigData> {
        self.by_namespace
            .get(ns)
            .into_iter()
            .flatten()
            .filter_map(|key| self.by_key.get(key))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn all(&self) -> &HashMap<Strng, WorkloadConfigData> {
        &self.by_key
    }

    /// Insert or replace an extension keyed by its xDS resource name.
    /// The `scope` from the proto resource determines how the extension is indexed:
    /// - Global scope: indexed under the empty string so it applies to all namespaces.
    /// - Namespace scope: indexed under the given `namespace`.
    pub fn insert(
        &mut self,
        key: Strng,
        namespace: Strng,
        scope: WorkloadConfigScope,
        data: WorkloadConfigData,
    ) {
        self.remove(key.clone());
        match scope {
            WorkloadConfigScope::Global => {
                self.by_namespace
                    .entry(crate::strng::EMPTY)
                    .or_default()
                    .insert(key.clone());
                self.key_to_namespace
                    .insert(key.clone(), crate::strng::EMPTY);
            }
            WorkloadConfigScope::Namespace => {
                self.by_namespace
                    .entry(namespace.clone())
                    .or_default()
                    .insert(key.clone());
                self.key_to_namespace.insert(key.clone(), namespace);
            }
        }
        self.by_key.insert(key, data);
    }

    pub fn remove(&mut self, key: Strng) {
        if self.by_key.remove(&key).is_some() {
            if let Some(ns) = self.key_to_namespace.remove(&key) {
                if let Some(keys) = self.by_namespace.get_mut(&ns) {
                    keys.remove(&key);
                    if keys.is_empty() {
                        self.by_namespace.remove(&ns);
                    }
                }
            }
        }
    }

    pub fn send(&mut self) {
        self.notifier.sender.send_replace(());
    }

    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.notifier.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::extensions::{EgressPolicy, EgressPolicyAction};

    fn make_data(action: EgressPolicyAction) -> WorkloadConfigData {
        WorkloadConfigData {
            egress_policies: EgressPolicies {
                policies: vec![EgressPolicy {
                    namespaces: Default::default(),
                    match_cidrs: vec![],
                    match_ports: vec![],
                    policy: action,
                    gateway: None,
                }],
            },
        }
    }

    #[test]
    fn insert_and_lookup_by_namespace() {
        let mut store = WorkloadConfigStore::default();
        store.insert(
            Strng::from("default/policy-a"),
            Strng::from("default"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Passthrough),
        );
        store.insert(
            Strng::from("default/policy-b"),
            Strng::from("default"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Deny),
        );
        store.insert(
            Strng::from("other/policy-c"),
            Strng::from("other"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Passthrough),
        );

        let default_policies = store.get_by_namespace(&Strng::from("default"));
        assert_eq!(default_policies.len(), 2);

        let other_policies = store.get_by_namespace(&Strng::from("other"));
        assert_eq!(other_policies.len(), 1);

        let missing = store.get_by_namespace(&Strng::from("no-such-ns"));
        assert!(missing.is_empty());
    }

    #[test]
    fn remove_cleans_up_secondary_index() {
        let mut store = WorkloadConfigStore::default();
        store.insert(
            Strng::from("default/policy-a"),
            Strng::from("default"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Passthrough),
        );
        assert_eq!(store.get_by_namespace(&Strng::from("default")).len(), 1);

        store.remove(Strng::from("default/policy-a"));
        assert!(store.get_by_namespace(&Strng::from("default")).is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn insert_replaces_existing_key() {
        let mut store = WorkloadConfigStore::default();
        store.insert(
            Strng::from("default/policy-a"),
            Strng::from("default"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Passthrough),
        );
        store.insert(
            Strng::from("default/policy-a"),
            Strng::from("default"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Deny),
        );
        let policies = store.get_by_namespace(&Strng::from("default"));
        assert_eq!(policies.len(), 1);
        assert_eq!(
            policies[0].egress_policies.policies[0].policy,
            EgressPolicyAction::Deny
        );
    }

    #[test]
    fn global_and_namespace_scoped_lookup() {
        let mut store = WorkloadConfigStore::default();
        store.insert(
            Strng::from("istio-system/global-policy"),
            Strng::from("istio-system"),
            WorkloadConfigScope::Global,
            make_data(EgressPolicyAction::Passthrough),
        );
        store.insert(
            Strng::from("default/ns-policy"),
            Strng::from("default"),
            WorkloadConfigScope::Namespace,
            make_data(EgressPolicyAction::Deny),
        );

        let mut all = store.get_by_namespace(&Strng::from("default"));
        all.extend(store.get_by_namespace(&crate::strng::EMPTY));
        assert_eq!(all.len(), 2);
    }
}
