use codex_protocol::ThreadId;
use codex_protocol::protocol::SessionSource;
use codex_rollout::read_session_meta_line;
use serde_json::Value;
use tracing::warn;

use super::LocalThreadStore;
use crate::ThreadStoreError;
use crate::ThreadStoreResult;

pub(super) async fn list_owned_descendant_thread_ids(
    store: &LocalThreadStore,
    root_thread_id: ThreadId,
) -> ThreadStoreResult<Vec<ThreadId>> {
    let Some(state_db) = store.state_db.as_ref() else {
        return Ok(Vec::new());
    };

    let unresolved = state_db
        .list_threads_with_unknown_parent_relation()
        .await
        .map_err(internal_error)?;
    let mut resolved = Vec::with_capacity(unresolved.len());
    for (thread_id, rollout_path, source) in unresolved {
        let source = serde_json::from_str::<SessionSource>(&source).or_else(|_| {
            serde_json::from_value::<SessionSource>(Value::String(source.to_string()))
        });
        if let Some(parent_thread_id) = source.ok().and_then(|source| source.parent_thread_id()) {
            resolved.push((thread_id, Some(parent_thread_id)));
            continue;
        }

        match read_session_meta_line(rollout_path.as_path()).await {
            Ok(meta_line) if meta_line.meta.id == thread_id => {
                resolved.push((thread_id, meta_line.meta.parent_thread_id));
            }
            Ok(meta_line) => {
                warn!(
                    "cannot index parent relation for {thread_id}: rollout metadata belongs to {}",
                    meta_line.meta.id
                );
            }
            Err(err) => {
                warn!(
                    "cannot index parent relation for {thread_id} from {}: {err}",
                    rollout_path.display()
                );
            }
        }
    }
    state_db
        .resolve_thread_parent_relations(&resolved)
        .await
        .map_err(internal_error)?;
    state_db
        .list_thread_parent_descendants(root_thread_id)
        .await
        .map_err(internal_error)
}

fn internal_error(err: impl std::fmt::Display) -> ThreadStoreError {
    ThreadStoreError::Internal {
        message: err.to_string(),
    }
}
