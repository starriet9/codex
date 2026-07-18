use crate::acl::revoke_ace;
use crate::deny_read_acl::apply_deny_read_acls;
use crate::deny_read_acl::lexical_path_key;
use crate::setup::sandbox_dir;
use crate::to_wide;
use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::ReleaseMutex;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const DENY_READ_ACL_STATE_FILE: &str = "deny_read_acl_state.json";
const DENY_READ_ACL_STATE_MUTEX_NAME: &str = "Local\\CodexSandboxDenyReadAclState";
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x0000_0080;
const WAIT_FAILED: u32 = u32::MAX;

#[derive(Default, Deserialize, Serialize)]
struct PersistentDenyReadAclState {
    principals: BTreeMap<String, Vec<PathBuf>>,
}

/// Reconciles the persistent deny-read ACEs owned by one sandbox principal.
///
/// Workspace-write and elevated sandbox sessions intentionally leave ACLs in
/// place after a command exits, because descendants may outlive the launcher.
/// That makes the ACL set stateful across runs. Persist the paths applied for
/// each SID, apply the new desired set first, and only then revoke stale paths
/// from the same SID so profile changes do not leave old deny-read ACEs behind.
///
/// # Safety
/// Caller must pass a valid SID pointer matching `principal_sid`.
pub unsafe fn sync_persistent_deny_read_acls(
    codex_home: &Path,
    principal_sid: &str,
    desired_paths: &[PathBuf],
    psid: *mut c_void,
) -> Result<Vec<PathBuf>> {
    let state_path = sandbox_dir(codex_home).join(DENY_READ_ACL_STATE_FILE);
    update_state(&state_path, |state| {
        let previous_paths = state
            .principals
            .get(principal_sid)
            .cloned()
            .unwrap_or_default();

        let applied_paths = unsafe { apply_deny_read_acls(desired_paths, psid) }?;
        let desired_keys = applied_paths
            .iter()
            .map(|path| lexical_path_key(path))
            .collect::<HashSet<_>>();

        for path in previous_paths {
            if !desired_keys.contains(&lexical_path_key(&path)) {
                revoke_ace(&path, psid);
            }
        }

        if applied_paths.is_empty() {
            state.principals.remove(principal_sid);
        } else {
            state
                .principals
                .insert(principal_sid.to_string(), applied_paths.clone());
        }

        Ok(applied_paths)
    })
}

fn update_state<T>(
    path: &Path,
    update: impl FnOnce(&mut PersistentDenyReadAclState) -> Result<T>,
) -> Result<T> {
    update_state_with_mutex_name(path, DENY_READ_ACL_STATE_MUTEX_NAME, update)
}

fn update_state_with_mutex_name<T>(
    path: &Path,
    mutex_name: &str,
    update: impl FnOnce(&mut PersistentDenyReadAclState) -> Result<T>,
) -> Result<T> {
    // ACL reconciliation and persistence form one cross-process transaction.
    // Locking only the JSON write would still allow stale reads and lost updates.
    let _guard = DenyReadAclStateMutexGuard::acquire(mutex_name)
        .context("acquire deny-read ACL state mutex")?;
    let mut state = load_state(path)?;
    let output = update(&mut state)?;
    store_state(path, &state)?;
    Ok(output)
}

struct DenyReadAclStateMutexGuard {
    handle: HANDLE,
}

impl DenyReadAclStateMutexGuard {
    fn acquire(name: &str) -> Result<Self> {
        let name = to_wide(OsStr::new(name));
        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr()) };
        if handle == 0 {
            return Err(anyhow::anyhow!("CreateMutexW failed: {}", unsafe {
                GetLastError()
            }));
        }

        let wait_result = unsafe { WaitForSingleObject(handle, INFINITE) };
        match wait_result {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self { handle }),
            WAIT_FAILED => {
                let error = unsafe { GetLastError() };
                unsafe {
                    CloseHandle(handle);
                }
                Err(anyhow::anyhow!("WaitForSingleObject failed: {error}"))
            }
            other => {
                unsafe {
                    CloseHandle(handle);
                }
                Err(anyhow::anyhow!(
                    "WaitForSingleObject returned unexpected status: {other}"
                ))
            }
        }
    }
}

impl Drop for DenyReadAclStateMutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

fn load_state(path: &Path) -> Result<PersistentDenyReadAclState> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse deny-read ACL state {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(PersistentDenyReadAclState::default())
        }
        Err(err) => {
            Err(err).with_context(|| format!("read deny-read ACL state {}", path.display()))
        }
    }
}

fn store_state(path: &Path, state: &PersistentDenyReadAclState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state).context("serialize deny-read ACL state")?;
    let parent = path
        .parent()
        .with_context(|| format!("deny-read ACL state path has no parent: {}", path.display()))?;
    // Keep the previous complete JSON visible until its replacement is ready.
    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "create temporary deny-read ACL state in {}",
            parent.display()
        )
    })?;
    temporary
        .write_all(&bytes)
        .with_context(|| format!("write temporary deny-read ACL state for {}", path.display()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .with_context(|| format!("sync temporary deny-read ACL state for {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace deny-read ACL state {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;
    use tempfile::TempDir;

    const CHILD_STATE_PATH_ENV: &str = "CODEX_TEST_DENY_READ_STATE_PATH";
    const CHILD_MUTEX_NAME_ENV: &str = "CODEX_TEST_DENY_READ_MUTEX_NAME";
    const CHILD_PRINCIPAL_ENV: &str = "CODEX_TEST_DENY_READ_PRINCIPAL";
    const CHILD_READY_PATH_ENV: &str = "CODEX_TEST_DENY_READ_READY_PATH";
    const CHILD_START_PATH_ENV: &str = "CODEX_TEST_DENY_READ_START_PATH";

    #[test]
    fn concurrent_updates_preserve_all_principals() {
        const WRITER_COUNT: usize = 8;

        let temp = TempDir::new().expect("create temp dir");
        let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
        let mutex_name = format!(
            "Local\\CodexSandboxDenyReadAclStateThreadTest-{}",
            std::process::id()
        );
        let start = Arc::new(Barrier::new(WRITER_COUNT));
        let mut writers = Vec::new();

        for index in 0..WRITER_COUNT {
            let state_path = state_path.clone();
            let mutex_name = mutex_name.clone();
            let start = Arc::clone(&start);
            writers.push(thread::spawn(move || {
                start.wait();
                update_state_with_mutex_name(&state_path, &mutex_name, |state| {
                    thread::sleep(Duration::from_millis(100));
                    state.principals.insert(
                        format!("S-1-5-21-test-{index}"),
                        vec![PathBuf::from(format!(r"C:\deny-{index}"))],
                    );
                    Ok(())
                })
                .expect("update state");
            }));
        }

        for writer in writers {
            writer.join().expect("join writer");
        }

        let state = load_state(&state_path).expect("load final state");
        assert_eq!(state.principals.len(), WRITER_COUNT);
    }

    #[test]
    fn concurrent_process_updates_preserve_all_principals() {
        if std::env::var_os(CHILD_STATE_PATH_ENV).is_some() {
            run_process_update_child();
            return;
        }

        const WRITER_COUNT: usize = 6;
        const CHILD_TEST_NAME: &str =
            "deny_read_state::tests::concurrent_process_updates_preserve_all_principals";

        let temp = TempDir::new().expect("create temp dir");
        let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
        let start_path = temp.path().join("start");
        let mutex_name = format!(
            "Local\\CodexSandboxDenyReadAclStateProcessTest-{}",
            std::process::id()
        );
        let test_exe = std::env::current_exe().expect("resolve test executable");
        let mut children = Vec::new();
        let mut ready_paths = Vec::new();

        for index in 0..WRITER_COUNT {
            let ready_path = temp.path().join(format!("ready-{index}"));
            let child = Command::new(&test_exe)
                .args(["--exact", CHILD_TEST_NAME, "--nocapture"])
                .env(CHILD_STATE_PATH_ENV, &state_path)
                .env(CHILD_MUTEX_NAME_ENV, &mutex_name)
                .env(CHILD_PRINCIPAL_ENV, format!("S-1-5-21-process-{index}"))
                .env(CHILD_READY_PATH_ENV, &ready_path)
                .env(CHILD_START_PATH_ENV, &start_path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn child writer");
            children.push(child);
            ready_paths.push(ready_path);
        }

        let ready_deadline = Instant::now() + Duration::from_secs(15);
        while !ready_paths.iter().all(|path| path.exists()) {
            assert!(
                Instant::now() < ready_deadline,
                "child writers did not become ready"
            );
            thread::sleep(Duration::from_millis(10));
        }
        std::fs::write(&start_path, b"start").expect("release child writers");

        for child in children {
            let output = child.wait_with_output().expect("wait for child writer");
            assert!(
                output.status.success(),
                "child writer failed: status={}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let state = load_state(&state_path).expect("load final state");
        assert_eq!(state.principals.len(), WRITER_COUNT);
    }

    fn run_process_update_child() {
        let state_path = PathBuf::from(
            std::env::var_os(CHILD_STATE_PATH_ENV).expect("state path environment variable"),
        );
        let mutex_name =
            std::env::var(CHILD_MUTEX_NAME_ENV).expect("mutex name environment variable");
        let principal = std::env::var(CHILD_PRINCIPAL_ENV).expect("principal environment variable");
        let ready_path = PathBuf::from(
            std::env::var_os(CHILD_READY_PATH_ENV).expect("ready path environment variable"),
        );
        let start_path = PathBuf::from(
            std::env::var_os(CHILD_START_PATH_ENV).expect("start path environment variable"),
        );

        std::fs::write(&ready_path, b"ready").expect("mark child ready");
        let start_deadline = Instant::now() + Duration::from_secs(15);
        while !start_path.exists() {
            assert!(
                Instant::now() < start_deadline,
                "parent did not release child writer"
            );
            thread::sleep(Duration::from_millis(10));
        }

        update_state_with_mutex_name(&state_path, &mutex_name, |state| {
            thread::sleep(Duration::from_millis(100));
            state
                .principals
                .insert(principal, vec![PathBuf::from(r"C:\process-deny")]);
            Ok(())
        })
        .expect("update state from child process");
    }
}
