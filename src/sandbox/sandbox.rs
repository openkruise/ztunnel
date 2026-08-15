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

use base64::Engine;

use crate::watcher::watcher::{AsyncFileWatcher, FileStore};

pub static SANDBOX_TOKEN_HEADER: &str = "x-agentio-sandbox-token";
pub static SANDBOX_ID_HEADER: &str = "x-agentio-sandbox-id";
pub static SANDBOX_GENERATION_HEADER: &str = "x-agentio-sandbox-generation";
pub static SANDBOX_LABELS_HEADER: &str = "x-agentio-sandbox-labels";

// Debounce window for the sandbox token watcher. K8s ConfigMap/Secret remounts
// fire several events in rapid succession; coalescing for 2s keeps the store
// from churning while a remount is in progress.
const SANDBOX_WATCHER_DEBOUNCE_MS: u64 = 2000;

/// Transform a raw token file content into the value stored in [`FileStore`].
/// Wraps the bytes in standard base64 so downstream consumers can ship them
/// in HTTP headers (`x-agentio-sandbox-token`) without worrying about binary or
/// CRLF content.
pub(crate) fn sandbox_token_transform(s: String) -> anyhow::Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(s))
}

/// Derive the [`FileStore`] key from a token file path.
/// Returns the file stem (filename without extension); K8s atomic-write mounts
/// create files like `<sandbox-id>.token`, so the stem matches the sandbox id
/// the proxy uses to look the token up.
pub(crate) fn sandbox_token_key(path: &PathBuf) -> Option<String> {
    path.file_stem().map(|s| s.to_string_lossy().to_string())
}

/// Manages sandbox tokens by watching all files in the token directory.
pub struct SandboxManager {
    store: Option<Arc<FileStore<String, String>>>,
    _watcher_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SandboxManager {
    pub fn new() -> Self {
        SandboxManager {
            store: None,
            _watcher_handle: None,
        }
    }

    pub async fn run(&mut self, token_dir: PathBuf) {
        tracing::info!(
            "sandbox mode enabled - starting directory watcher for {:?}",
            token_dir,
        );

        let store = Arc::new(FileStore::new(sandbox_token_transform, sandbox_token_key));

        let watcher = AsyncFileWatcher::new(store.clone(), token_dir)
            .with_debounce_ms(SANDBOX_WATCHER_DEBOUNCE_MS);

        match watcher.start().await {
            Ok(handle) => {
                tracing::info!("sandbox token watcher started");
                self._watcher_handle = Some(handle);
                self.store = Some(store);
            }
            Err(e) => {
                // Failing here leaves `store` as None; all token lookups will
                // return empty/None, which surfaces as 401/empty header upstream
                // rather than a crash.
                tracing::error!("failed to start sandbox token watcher: {}", e);
            }
        }
    }

    pub fn list_sandbox_tokens(&self) -> Vec<Arc<String>> {
        self.store.as_ref().map_or(vec![], |s| s.values())
    }

    pub fn get_sandbox_token(&self, sandbox_id: String) -> Option<Arc<String>> {
        match self.store {
            None => None,
            Some(ref store) => store.get(&sandbox_id).map(|v| v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_transform_base64_encodes_bytes() {
        // "hello" -> "aGVsbG8=" (standard alphabet, with padding)
        let got = sandbox_token_transform("hello".to_string()).expect("transform");
        assert_eq!(got, "aGVsbG8=");
    }

    #[test]
    fn token_transform_handles_empty_input() {
        // Empty input must produce empty output (not error); K8s briefly writes
        // empty files during atomic remount.
        let got = sandbox_token_transform(String::new()).expect("transform");
        assert_eq!(got, "");
    }

    #[test]
    fn token_transform_preserves_binary_content_via_base64() {
        // Round-trip through base64 to make sure non-ASCII bytes survive.
        let raw = "tok\nwith\rweird\x00bytes";
        let encoded = sandbox_token_transform(raw.to_string()).expect("transform");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("decode");
        assert_eq!(decoded.as_slice(), raw.as_bytes());
    }

    #[test]
    fn token_key_extracts_file_stem() {
        let key = sandbox_token_key(&PathBuf::from("/var/opt/sandbox/sb-123.token"));
        assert_eq!(key, Some("sb-123".to_string()));
    }

    #[test]
    fn token_key_extracts_stem_for_file_without_extension() {
        let key = sandbox_token_key(&PathBuf::from("/var/opt/sandbox/sb-456"));
        assert_eq!(key, Some("sb-456".to_string()));
    }

    #[test]
    fn token_key_handles_k8s_atomic_mount_dotfile() {
        // K8s atomic writes create directory entries like `..data` (symlink to
        // a timestamped dir). Path::file_stem treats the leading dot as the
        // "beginning" of the name and splits at the next dot, so `..data`
        // stems to ".". This is acceptable: "." is not a valid sandbox id, so
        // lookups for the symlink entry return None.
        let key = sandbox_token_key(&PathBuf::from("/var/opt/sandbox/..data"));
        assert_eq!(key, Some(".".to_string()));
    }

    #[test]
    fn token_key_returns_none_for_root_path() {
        // No file component means no sandbox id; the watcher will skip the
        // event entirely (see FileStore::handle_change).
        assert_eq!(sandbox_token_key(&PathBuf::from("/")), None);
    }

    #[test]
    fn token_key_strips_only_final_extension() {
        // Path like `foo.tar.gz` stems to `foo.tar`; this is fine because
        // sandbox token files are named `<id>.token`, not double-extensioned.
        let key = sandbox_token_key(&PathBuf::from("foo.tar.gz"));
        assert_eq!(key, Some("foo.tar".to_string()));
    }

    #[test]
    fn manager_new_returns_empty_state() {
        let mgr = SandboxManager::new();
        assert!(mgr.list_sandbox_tokens().is_empty());
        assert!(mgr.get_sandbox_token("any-id".to_string()).is_none());
    }

    #[test]
    fn manager_lookups_before_run_are_safe() {
        // Calling lookup methods before `run()` must not panic and must return
        // empty/None - this is the failure mode we want when the watcher fails
        // to start (e.g. directory missing in an unprivileged sandbox).
        let mgr = SandboxManager::new();
        let tokens = mgr.list_sandbox_tokens();
        let token = mgr.get_sandbox_token("anything".to_string());
        assert!(tokens.is_empty());
        assert!(token.is_none());
    }

    #[test]
    fn header_constants_have_expected_values() {
        // These header names are part of the on-the-wire contract with the
        // egress gateway; changing them is a breaking change.
        assert_eq!(SANDBOX_TOKEN_HEADER, "x-agentio-sandbox-token");
        assert_eq!(SANDBOX_ID_HEADER, "x-agentio-sandbox-id");
        assert_eq!(SANDBOX_GENERATION_HEADER, "x-agentio-sandbox-generation");
        assert_eq!(SANDBOX_LABELS_HEADER, "x-agentio-sandbox-labels");
    }
}
