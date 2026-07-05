//! Diagnoses Codex Desktop browser-runtime handoff state.
//!
//! The Desktop app and bundled browser plugins can leave runtime paths in
//! config files that are consumed by browser-use tooling. This check is
//! read-only: it compares the values written by Desktop with the native-host
//! config that launches helper processes, without attempting to refresh either.

use std::collections::HashMap;
use std::env;
#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::path::PathBuf;

use codex_config::types::McpServerConfig;
use codex_config::types::McpServerTransportConfig;
use serde::Deserialize;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::HKEY;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::RRF_RT_REG_EXPAND_SZ;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::RRF_RT_REG_SZ;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::RegGetValueW;

use super::CheckStatus;
use super::DoctorCheck;
use super::DoctorIssue;
use super::normalize_path_for_compare;

const CHROME_NATIVE_HOSTS_JSON: &str = "chrome-native-hosts.json";
const CHROME_PLUGIN_MANIFEST: &str =
    "plugins/cache/openai-bundled/chrome/latest/.codex-plugin/plugin.json";
const NODE_REPL_MCP_SERVER: &str = "node_repl";
const CODEX_CLI_PATH: &str = "CODEX_CLI_PATH";
const NODE_REPL_NODE_PATH: &str = "NODE_REPL_NODE_PATH";
const NODE_REPL_NODE_MODULE_DIRS: &str = "NODE_REPL_NODE_MODULE_DIRS";

pub(super) fn desktop_runtime_check(
    codex_home: &Path,
    mcp_servers: &HashMap<String, McpServerConfig>,
) -> DoctorCheck {
    let runtime_config = desktop_runtime_config_from_mcp_servers(mcp_servers);
    let codex_cli_path_env = read_codex_cli_path_env_snapshots();
    let installed_chrome_plugin_version = read_installed_chrome_plugin_version(codex_home).ok();
    let mut manifest_errors = Vec::new();
    let mut hosts = Vec::new();

    for path in native_host_config_paths(codex_home) {
        if !path.exists() {
            continue;
        }
        match read_native_hosts_file(&path) {
            Ok(file) => {
                for host in file.chrome_native_hosts {
                    hosts.push(NativeHostSnapshot {
                        path: path.clone(),
                        host,
                    });
                }
            }
            Err(err) => manifest_errors.push((path, err)),
        }
    }

    desktop_runtime_check_from_snapshots(
        runtime_config,
        codex_cli_path_env,
        installed_chrome_plugin_version,
        manifest_errors,
        hosts,
    )
}

fn desktop_runtime_check_from_snapshots(
    runtime_config: DesktopRuntimeConfig,
    codex_cli_path_env: Vec<CodexCliPathEnvSnapshot>,
    installed_chrome_plugin_version: Option<String>,
    manifest_errors: Vec<(PathBuf, String)>,
    hosts: Vec<NativeHostSnapshot>,
) -> DoctorCheck {
    let mut details = Vec::new();
    let mut issues = Vec::new();

    match &runtime_config.codex_cli_path {
        Some(path) => details.push(format!("configured CODEX_CLI_PATH: {}", path.display())),
        None => details.push("configured CODEX_CLI_PATH: not set".to_string()),
    }
    append_codex_cli_path_env_details_and_issues(
        &runtime_config,
        &codex_cli_path_env,
        &mut details,
        &mut issues,
    );

    match &runtime_config.codex_app_browser_plugin_version {
        Some(version) => details.push(format!(
            "configured Codex App browser plugin version: {version}"
        )),
        None => details.push("configured Codex App browser plugin version: not set".to_string()),
    }
    match &installed_chrome_plugin_version {
        Some(version) => details.push(format!("installed Chrome plugin version: {version}")),
        None => details.push("installed Chrome plugin version: not found".to_string()),
    }

    append_node_repl_runtime_details_and_issues(&runtime_config, &mut details, &mut issues);

    if hosts.is_empty() && manifest_errors.is_empty() {
        if !issues.is_empty() {
            return desktop_runtime_check_with_issues(details, issues);
        }
        return DoctorCheck::new(
            "desktop.browser_runtime",
            "desktop",
            CheckStatus::Ok,
            "desktop browser native-host config not found",
        )
        .details(details);
    }

    for (path, error) in manifest_errors {
        details.push(format!("native-host config {}: {error}", path.display()));
        issues.push(
            DoctorIssue::new(
                CheckStatus::Warning,
                "desktop browser native-host config could not be read",
            )
            .measured(format!("{}: {error}", path.display()))
            .remedy("Restart Codex after updating Codex Desktop. If the problem persists, reinstall Codex Desktop."),
        );
    }

    for snapshot in hosts {
        let NativeHostSnapshot { path, host } = snapshot;
        let source = path.display().to_string();
        details.push(format!("native-host config: {source}"));

        if let Some(plugin_version) = &host.plugin_version {
            details.push(format!("native-host pluginVersion: {plugin_version}"));
            if let Some(expected) = runtime_config
                .codex_app_browser_plugin_version
                .as_ref()
                .or(installed_chrome_plugin_version.as_ref())
            {
                if plugin_version != expected {
                    issues.push(
                        DoctorIssue::new(
                            CheckStatus::Warning,
                            "desktop browser native-host pluginVersion is stale",
                        )
                        .measured(plugin_version.clone())
                        .expected(expected.clone())
                        .remedy("Restart Codex after updating Codex Desktop. If the mismatch persists, reload bundled plugins or reinstall Codex Desktop.")
                        .field("pluginVersion"),
                    );
                }
            }
        } else {
            details.push("native-host pluginVersion: not set".to_string());
        }

        if let Some(codex_cli_path) = &host.codex_cli_path {
            details.push(format!(
                "native-host codexCliPath: {}",
                codex_cli_path.display()
            ));
            if !codex_cli_path.exists() {
                issues.push(
                    DoctorIssue::new(
                        CheckStatus::Warning,
                        "desktop browser native-host codexCliPath target is missing",
                    )
                    .measured(codex_cli_path.display().to_string())
                    .remedy("Restart Codex after updating Codex Desktop. If the path remains missing, reinstall Codex Desktop.")
                    .field("codexCliPath"),
                );
            }
            if let Some(expected) = &runtime_config.codex_cli_path {
                if !same_path(codex_cli_path, expected) {
                    issues.push(
                        DoctorIssue::new(
                            CheckStatus::Warning,
                            "desktop browser native-host codexCliPath does not match configured CODEX_CLI_PATH",
                        )
                        .measured(codex_cli_path.display().to_string())
                        .expected(expected.display().to_string())
                        .remedy("Restart Codex after updating Codex Desktop. If the mismatch persists, reload bundled plugins or reinstall Codex Desktop.")
                        .field("codexCliPath"),
                    );
                }
            }
        } else {
            details.push("native-host codexCliPath: not set".to_string());
        }

        if let Some(node_repl_path) = &host.node_repl_path {
            details.push(format!(
                "native-host nodeReplPath: {}",
                node_repl_path.display()
            ));
        }
        if let Some(resources_path) = &host.resources_path {
            details.push(format!(
                "native-host resourcesPath: {}",
                resources_path.display()
            ));
        }
    }

    let status = if issues.is_empty() {
        CheckStatus::Ok
    } else {
        CheckStatus::Warning
    };
    let summary = if issues.is_empty() {
        "desktop browser runtime config looks consistent"
    } else {
        "desktop browser runtime config may be stale"
    };

    desktop_runtime_check_with_status_and_summary(details, issues, status, summary)
}

fn desktop_runtime_check_with_issues(
    details: Vec<String>,
    issues: Vec<DoctorIssue>,
) -> DoctorCheck {
    desktop_runtime_check_with_status_and_summary(
        details,
        issues,
        CheckStatus::Warning,
        "desktop browser runtime config may be stale",
    )
}

fn desktop_runtime_check_with_status_and_summary(
    details: Vec<String>,
    issues: Vec<DoctorIssue>,
    status: CheckStatus,
    summary: &str,
) -> DoctorCheck {
    let mut check =
        DoctorCheck::new("desktop.browser_runtime", "desktop", status, summary).details(details);
    if status != CheckStatus::Ok {
        check = check.remediation(
            "Restart Codex after updating Codex Desktop. If stale paths persist, reload bundled plugins or reinstall Codex Desktop.",
        );
    }
    for issue in issues {
        check = check.issue(issue);
    }
    check
}

fn append_codex_cli_path_env_details_and_issues(
    runtime_config: &DesktopRuntimeConfig,
    snapshots: &[CodexCliPathEnvSnapshot],
    details: &mut Vec<String>,
    issues: &mut Vec<DoctorIssue>,
) {
    for snapshot in snapshots {
        let field = format!("{} {CODEX_CLI_PATH}", snapshot.source);
        match &snapshot.path {
            Some(path) => {
                details.push(format!("{field}: {}", path.display()));
                if !path.exists() {
                    issues.push(
                        DoctorIssue::new(
                            CheckStatus::Warning,
                            format!("{field} target is missing"),
                        )
                        .measured(path.display().to_string())
                        .remedy("Update or remove the stale CODEX_CLI_PATH environment variable, then fully restart Codex Desktop and Codex CLI.")
                        .field(field.clone()),
                    );
                }
                if let Some(expected) = &runtime_config.codex_cli_path
                    && !same_path(path, expected)
                {
                    issues.push(
                        DoctorIssue::new(
                            CheckStatus::Warning,
                            format!("{field} does not match configured CODEX_CLI_PATH"),
                        )
                        .measured(path.display().to_string())
                        .expected(expected.display().to_string())
                        .remedy("Update or remove the stale CODEX_CLI_PATH environment variable, then fully restart Codex Desktop and Codex CLI.")
                        .field(field),
                    );
                }
            }
            None => details.push(format!("{field}: not set")),
        }
    }
}

fn append_node_repl_runtime_details_and_issues(
    runtime_config: &DesktopRuntimeConfig,
    details: &mut Vec<String>,
    issues: &mut Vec<DoctorIssue>,
) {
    match &runtime_config.node_repl_command {
        Some(command) => {
            details.push(format!(
                "configured node_repl command: {}",
                command.display()
            ));
            if explicit_path(command) && !command.exists() {
                issues.push(missing_runtime_path_issue(
                    "configured node_repl command target is missing",
                    "mcp_servers.node_repl.command",
                    command,
                ));
            }
        }
        None => details.push("configured node_repl command: not set".to_string()),
    }

    match &runtime_config.node_repl_node_path {
        Some(path) => {
            details.push(format!(
                "configured {NODE_REPL_NODE_PATH}: {}",
                path.display()
            ));
            if !path.exists() {
                issues.push(missing_runtime_path_issue(
                    "configured NODE_REPL_NODE_PATH target is missing",
                    NODE_REPL_NODE_PATH,
                    path,
                ));
            }
        }
        None => details.push(format!("configured {NODE_REPL_NODE_PATH}: not set")),
    }

    if runtime_config.node_repl_node_module_dirs.is_empty() {
        details.push(format!("configured {NODE_REPL_NODE_MODULE_DIRS}: not set"));
    } else {
        for path in &runtime_config.node_repl_node_module_dirs {
            details.push(format!(
                "configured {NODE_REPL_NODE_MODULE_DIRS}: {}",
                path.display()
            ));
            if !path.exists() {
                issues.push(missing_runtime_path_issue(
                    "configured NODE_REPL_NODE_MODULE_DIRS entry is missing",
                    NODE_REPL_NODE_MODULE_DIRS,
                    path,
                ));
            }
        }
    }
}

fn missing_runtime_path_issue(cause: &str, field: &str, path: &Path) -> DoctorIssue {
    DoctorIssue::new(CheckStatus::Warning, cause)
        .measured(path.display().to_string())
        .remedy("Restart Codex after updating Codex Desktop. If the path remains missing, relaunch or reinstall Codex Desktop.")
        .field(field)
}

fn native_host_config_paths(codex_home: &Path) -> Vec<PathBuf> {
    let mut paths = vec![codex_home.join(CHROME_NATIVE_HOSTS_JSON)];
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        paths.push(
            PathBuf::from(local_app_data)
                .join("OpenAI")
                .join("Codex")
                .join(CHROME_NATIVE_HOSTS_JSON),
        );
    }
    paths.sort();
    paths.dedup();
    paths
}

fn desktop_runtime_config_from_mcp_servers(
    mcp_servers: &HashMap<String, McpServerConfig>,
) -> DesktopRuntimeConfig {
    let Some(server) = mcp_servers.get(NODE_REPL_MCP_SERVER) else {
        return DesktopRuntimeConfig::default();
    };
    match &server.transport {
        McpServerTransportConfig::Stdio { command, env, .. } => {
            desktop_runtime_config_from_node_repl_stdio(command, env.as_ref())
        }
        McpServerTransportConfig::StreamableHttp { .. } => DesktopRuntimeConfig::default(),
    }
}

fn desktop_runtime_config_from_node_repl_stdio(
    command: &str,
    env: Option<&HashMap<String, String>>,
) -> DesktopRuntimeConfig {
    let mut config = desktop_runtime_config_from_node_repl_env(env);
    config.node_repl_command = Some(PathBuf::from(command));
    config
}

fn desktop_runtime_config_from_node_repl_env(
    env: Option<&HashMap<String, String>>,
) -> DesktopRuntimeConfig {
    let Some(env) = env else {
        return DesktopRuntimeConfig::default();
    };
    DesktopRuntimeConfig {
        codex_cli_path: env.get(CODEX_CLI_PATH).map(PathBuf::from),
        codex_app_browser_plugin_version: env.get("BROWSER_USE_CODEX_APP_VERSION").cloned(),
        node_repl_command: None,
        node_repl_node_path: env.get(NODE_REPL_NODE_PATH).map(PathBuf::from),
        node_repl_node_module_dirs: env
            .get(NODE_REPL_NODE_MODULE_DIRS)
            .map(|value| env::split_paths(value).collect())
            .unwrap_or_default(),
    }
}

fn read_codex_cli_path_env_snapshots() -> Vec<CodexCliPathEnvSnapshot> {
    let mut snapshots = vec![CodexCliPathEnvSnapshot {
        source: "process environment",
        path: env::var_os(CODEX_CLI_PATH)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
    }];

    #[cfg(target_os = "windows")]
    {
        snapshots.push(CodexCliPathEnvSnapshot {
            source: "Windows user environment",
            path: read_windows_environment_path(HKEY_CURRENT_USER, "Environment", CODEX_CLI_PATH),
        });
        snapshots.push(CodexCliPathEnvSnapshot {
            source: "Windows machine environment",
            path: read_windows_environment_path(
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                CODEX_CLI_PATH,
            ),
        });
    }

    snapshots
}

#[cfg(target_os = "windows")]
fn read_windows_environment_path(root: HKEY, key: &str, name: &str) -> Option<PathBuf> {
    let value = read_windows_registry_string(root, key, name)?;
    let expanded = expand_windows_environment_string(&value);
    if expanded.is_empty() {
        None
    } else {
        Some(PathBuf::from(expanded))
    }
}

#[cfg(target_os = "windows")]
fn read_windows_registry_string(root: HKEY, key: &str, name: &str) -> Option<String> {
    let key = windows_wide_string(key);
    let name = windows_wide_string(name);
    let mut value_type = 0u32;
    let mut byte_len = 0u32;
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            name.as_ptr(),
            flags,
            &mut value_type,
            std::ptr::null_mut(),
            &mut byte_len,
        )
    };
    if status != 0 || byte_len == 0 {
        return None;
    }

    let mut buffer = vec![0u16; byte_len.div_ceil(2) as usize];
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            name.as_ptr(),
            flags,
            &mut value_type,
            buffer.as_mut_ptr().cast(),
            &mut byte_len,
        )
    };
    if status != 0 {
        return None;
    }

    let mut code_units = (byte_len / 2) as usize;
    if code_units > 0 && buffer.get(code_units - 1) == Some(&0) {
        code_units -= 1;
    }
    let value = OsString::from_wide(&buffer[..code_units])
        .to_string_lossy()
        .trim()
        .to_string();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(target_os = "windows")]
fn expand_windows_environment_string(value: &str) -> String {
    let input = windows_wide_string(value);
    let required = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if required == 0 {
        return value.to_string();
    }

    let mut buffer = vec![0u16; required as usize];
    let written = unsafe {
        ExpandEnvironmentStringsW(input.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
    };
    if written == 0 {
        return value.to_string();
    }

    let code_units = written.saturating_sub(1) as usize;
    OsString::from_wide(&buffer[..code_units])
        .to_string_lossy()
        .into_owned()
}

#[cfg(target_os = "windows")]
fn windows_wide_string(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn read_installed_chrome_plugin_version(codex_home: &Path) -> Result<String, String> {
    let path = codex_home.join(CHROME_PLUGIN_MANIFEST);
    let contents = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
    let manifest: PluginManifest =
        serde_json::from_str(&contents).map_err(|err| err.to_string())?;
    Ok(manifest.version)
}

fn read_native_hosts_file(path: &Path) -> Result<ChromeNativeHostsFile, String> {
    let contents = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str(&contents).map_err(|err| err.to_string())
}

fn same_path(left: &Path, right: &Path) -> bool {
    normalize_path_for_compare(left) == normalize_path_for_compare(right)
}

fn explicit_path(path: &Path) -> bool {
    path.is_absolute() || path.components().count() > 1
}

#[derive(Clone, Debug, Default)]
struct DesktopRuntimeConfig {
    codex_cli_path: Option<PathBuf>,
    codex_app_browser_plugin_version: Option<String>,
    node_repl_command: Option<PathBuf>,
    node_repl_node_path: Option<PathBuf>,
    node_repl_node_module_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
struct CodexCliPathEnvSnapshot {
    source: &'static str,
    path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct NativeHostSnapshot {
    path: PathBuf,
    host: ChromeNativeHost,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChromeNativeHostsFile {
    #[serde(default)]
    chrome_native_hosts: Vec<ChromeNativeHost>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChromeNativeHost {
    codex_cli_path: Option<PathBuf>,
    node_repl_path: Option<PathBuf>,
    plugin_version: Option<String>,
    resources_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct PluginManifest {
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_runtime_warns_for_stale_native_host_values() {
        let configured_path =
            PathBuf::from("C:/Users/example/AppData/Local/OpenAI/Codex/bin/new/codex.exe");
        let stale_path =
            PathBuf::from("C:/Users/example/AppData/Local/OpenAI/Codex/bin/old/codex.exe");
        let configured_path_display = configured_path.display().to_string();
        let stale_path_display = stale_path.display().to_string();
        let check = desktop_runtime_check_from_snapshots(
            DesktopRuntimeConfig {
                codex_cli_path: Some(configured_path.clone()),
                codex_app_browser_plugin_version: Some("26.609.41114".to_string()),
                ..DesktopRuntimeConfig::default()
            },
            Vec::new(),
            Some("26.609.41114".to_string()),
            Vec::new(),
            vec![NativeHostSnapshot {
                path: PathBuf::from("C:/Users/example/.codex/chrome-native-hosts.json"),
                host: ChromeNativeHost {
                    codex_cli_path: Some(stale_path.clone()),
                    node_repl_path: Some(PathBuf::from(
                        "C:/Users/example/AppData/Local/OpenAI/Codex/bin/node/node_repl.exe",
                    )),
                    plugin_version: Some("26.527.31326".to_string()),
                    resources_path: None,
                },
            }],
        );

        assert_eq!(check.status, CheckStatus::Warning);
        assert_eq!(check.summary, "desktop browser runtime config may be stale");
        assert!(check.issues.iter().any(|issue| {
            issue.cause.contains("pluginVersion is stale")
                && issue.measured.as_deref() == Some("26.527.31326")
                && issue.expected.as_deref() == Some("26.609.41114")
        }));
        assert!(check.issues.iter().any(|issue| {
            issue.cause.contains("codexCliPath does not match")
                && issue.measured.as_deref() == Some(stale_path_display.as_str())
                && issue.expected.as_deref() == Some(configured_path_display.as_str())
        }));
    }

    #[test]
    fn desktop_runtime_ok_when_no_native_host_config_exists() {
        let check = desktop_runtime_check_from_snapshots(
            DesktopRuntimeConfig::default(),
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(check.status, CheckStatus::Ok);
        assert_eq!(
            check.summary,
            "desktop browser native-host config not found"
        );
    }

    #[test]
    fn desktop_runtime_warns_for_missing_node_repl_runtime_paths_without_native_host_config() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let missing_command = temp.path().join("old-runtime").join("node_repl.exe");
        let missing_node = temp.path().join("old-runtime").join("node.exe");
        let missing_modules = temp.path().join("old-runtime").join("node_modules");
        let missing_command_display = missing_command.display().to_string();
        let missing_node_display = missing_node.display().to_string();
        let missing_modules_display = missing_modules.display().to_string();
        let env = HashMap::from([
            (
                NODE_REPL_NODE_PATH.to_string(),
                missing_node_display.clone(),
            ),
            (
                NODE_REPL_NODE_MODULE_DIRS.to_string(),
                missing_modules_display.clone(),
            ),
        ]);
        let runtime_config =
            desktop_runtime_config_from_node_repl_stdio(&missing_command_display, Some(&env));

        let check = desktop_runtime_check_from_snapshots(
            runtime_config,
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(check.status, CheckStatus::Warning);
        assert_eq!(check.summary, "desktop browser runtime config may be stale");
        assert!(check.issues.iter().any(|issue| {
            issue.cause.contains("node_repl command target is missing")
                && issue.measured.as_deref() == Some(missing_command_display.as_str())
                && issue.fields == vec!["mcp_servers.node_repl.command".to_string()]
        }));
        assert!(check.issues.iter().any(|issue| {
            issue
                .cause
                .contains("NODE_REPL_NODE_PATH target is missing")
                && issue.measured.as_deref() == Some(missing_node_display.as_str())
                && issue.fields == vec![NODE_REPL_NODE_PATH.to_string()]
        }));
        assert!(check.issues.iter().any(|issue| {
            issue
                .cause
                .contains("NODE_REPL_NODE_MODULE_DIRS entry is missing")
                && issue.measured.as_deref() == Some(missing_modules_display.as_str())
                && issue.fields == vec![NODE_REPL_NODE_MODULE_DIRS.to_string()]
        }));
    }

    #[test]
    fn desktop_runtime_warns_for_missing_codex_cli_path_environment_value() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let missing_path = temp.path().join("old-runtime").join("codex.exe");
        let missing_path_display = missing_path.display().to_string();

        let check = desktop_runtime_check_from_snapshots(
            DesktopRuntimeConfig::default(),
            vec![CodexCliPathEnvSnapshot {
                source: "Windows user environment",
                path: Some(missing_path),
            }],
            None,
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(check.status, CheckStatus::Warning);
        assert_eq!(check.summary, "desktop browser runtime config may be stale");
        assert!(check.issues.iter().any(|issue| {
            issue
                .cause
                .contains("Windows user environment CODEX_CLI_PATH target is missing")
                && issue.measured.as_deref() == Some(missing_path_display.as_str())
                && issue.fields == vec!["Windows user environment CODEX_CLI_PATH".to_string()]
        }));
    }

    #[test]
    fn desktop_runtime_warns_for_codex_cli_path_environment_config_mismatch() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let configured_path = temp.path().join("configured").join("codex.exe");
        let env_path = temp.path().join("env").join("codex.exe");
        std::fs::create_dir_all(configured_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        std::fs::write(&configured_path, b"").unwrap();
        std::fs::write(&env_path, b"").unwrap();
        let configured_path_display = configured_path.display().to_string();
        let env_path_display = env_path.display().to_string();

        let check = desktop_runtime_check_from_snapshots(
            DesktopRuntimeConfig {
                codex_cli_path: Some(configured_path),
                ..DesktopRuntimeConfig::default()
            },
            vec![CodexCliPathEnvSnapshot {
                source: "Windows user environment",
                path: Some(env_path),
            }],
            None,
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(check.status, CheckStatus::Warning);
        assert_eq!(check.summary, "desktop browser runtime config may be stale");
        assert!(check.issues.iter().any(|issue| {
            issue.cause.contains(
                "Windows user environment CODEX_CLI_PATH does not match configured CODEX_CLI_PATH",
            ) && issue.measured.as_deref() == Some(env_path_display.as_str())
                && issue.expected.as_deref() == Some(configured_path_display.as_str())
                && issue.fields == vec!["Windows user environment CODEX_CLI_PATH".to_string()]
        }));
    }

    #[test]
    fn desktop_runtime_config_reads_node_repl_env() {
        let env = HashMap::from([
            (
                "CODEX_CLI_PATH".to_string(),
                r"C:\Users\example\AppData\Local\OpenAI\Codex\bin\new\codex.exe".to_string(),
            ),
            (
                "BROWSER_USE_CODEX_APP_VERSION".to_string(),
                "26.609.41114".to_string(),
            ),
            (
                NODE_REPL_NODE_PATH.to_string(),
                r"C:\Users\example\AppData\Local\OpenAI\Codex\runtimes\cua_node\new\bin\node.exe"
                    .to_string(),
            ),
            (
                NODE_REPL_NODE_MODULE_DIRS.to_string(),
                "runtime-node-modules".to_string(),
            ),
        ]);

        let config = desktop_runtime_config_from_node_repl_stdio(
            r"C:\Users\example\AppData\Local\OpenAI\Codex\runtimes\cua_node\new\bin\node_repl.exe",
            Some(&env),
        );

        assert_eq!(
            config.codex_cli_path.as_deref(),
            Some(Path::new(
                r"C:\Users\example\AppData\Local\OpenAI\Codex\bin\new\codex.exe"
            ))
        );
        assert_eq!(
            config.codex_app_browser_plugin_version.as_deref(),
            Some("26.609.41114")
        );
        assert_eq!(
            config.node_repl_command.as_deref(),
            Some(Path::new(
                r"C:\Users\example\AppData\Local\OpenAI\Codex\runtimes\cua_node\new\bin\node_repl.exe"
            ))
        );
        assert_eq!(
            config.node_repl_node_path.as_deref(),
            Some(Path::new(
                r"C:\Users\example\AppData\Local\OpenAI\Codex\runtimes\cua_node\new\bin\node.exe"
            ))
        );
        assert_eq!(
            config.node_repl_node_module_dirs,
            vec![PathBuf::from("runtime-node-modules")]
        );
    }
}
