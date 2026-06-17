//! Diagnoses Codex Desktop browser-runtime handoff state.
//!
//! The Desktop app and bundled browser plugins can leave runtime paths in
//! config files that are consumed by browser-use tooling. This check is
//! read-only: it compares the values written by Desktop with the native-host
//! config that launches helper processes, without attempting to refresh either.

use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::path::PathBuf;

use codex_config::types::McpServerConfig;
use codex_config::types::McpServerTransportConfig;
use serde::Deserialize;

use super::CheckStatus;
use super::DoctorCheck;
use super::DoctorIssue;
use super::normalize_path_for_compare;

const CHROME_NATIVE_HOSTS_JSON: &str = "chrome-native-hosts.json";
const CHROME_PLUGIN_MANIFEST: &str =
    "plugins/cache/openai-bundled/chrome/latest/.codex-plugin/plugin.json";
const NODE_REPL_MCP_SERVER: &str = "node_repl";

pub(super) fn desktop_runtime_check(
    codex_home: &Path,
    mcp_servers: &HashMap<String, McpServerConfig>,
) -> DoctorCheck {
    let runtime_config = desktop_runtime_config_from_mcp_servers(mcp_servers);
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
        installed_chrome_plugin_version,
        manifest_errors,
        hosts,
    )
}

fn desktop_runtime_check_from_snapshots(
    runtime_config: DesktopRuntimeConfig,
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

    if hosts.is_empty() && manifest_errors.is_empty() {
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
    let env = mcp_servers
        .get(NODE_REPL_MCP_SERVER)
        .and_then(|server| match &server.transport {
            McpServerTransportConfig::Stdio { env, .. } => env.as_ref(),
            McpServerTransportConfig::StreamableHttp { .. } => None,
        });
    desktop_runtime_config_from_node_repl_env(env)
}

fn desktop_runtime_config_from_node_repl_env(
    env: Option<&HashMap<String, String>>,
) -> DesktopRuntimeConfig {
    let Some(env) = env else {
        return DesktopRuntimeConfig::default();
    };
    DesktopRuntimeConfig {
        codex_cli_path: env.get("CODEX_CLI_PATH").map(PathBuf::from),
        codex_app_browser_plugin_version: env.get("BROWSER_USE_CODEX_APP_VERSION").cloned(),
    }
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

#[derive(Clone, Debug, Default)]
struct DesktopRuntimeConfig {
    codex_cli_path: Option<PathBuf>,
    codex_app_browser_plugin_version: Option<String>,
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
            },
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
        ]);

        let config = desktop_runtime_config_from_node_repl_env(Some(&env));

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
    }
}
