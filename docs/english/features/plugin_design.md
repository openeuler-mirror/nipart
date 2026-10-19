<!-- vim-markdown-toc GFM -->

* [Plugin Design](#plugin-design)
    * [Overview](#overview)
    * [Architecture](#architecture)
    * [Plugin Trait](#plugin-trait)
    * [IPC Protocol](#ipc-protocol)
    * [Plugin Discovery and Lifecycle](#plugin-discovery-and-lifecycle)
    * [Daemon-Side Plugin Management](#daemon-side-plugin-management)
    * [Implementing a Plugin](#implementing-a-plugin)

<!-- vim-markdown-toc -->

# Plugin Design

## Overview

Nipart supports an out-of-process plugin system. Each plugin runs as an
independent binary process that communicates with the nipart daemon via Unix
domain sockets. This architecture provides process isolation: a plugin crash
does not bring down the daemon, and plugins can be developed, tested, and
upgraded independently.

Currently, Nipart ships with the following plugins:

- **nipart-plugin-wifi**: Manages WiFi connections via wpa_supplicant
- **nipart-plugin-8021x**: Manages MACsec MKA key agreement via shuli-wired
- **nipart-plugin-ovs**: Manages Open vSwitch bridges and ports

A `nipart-plugin-demo` is also provided as a reference implementation.

## Architecture

```
┌─────────────┐    Unix Socket     ┌─────────────────────┐
│             │◄──────────────────►│ nipart-plugin-wifi   │
│             │  /var/run/nipart/  └─────────────────────┘
│   nipart    │  sockets/plugin/
│   daemon    │                    ┌─────────────────────┐
│             │◄──────────────────►│ nipart-plugin-ovs    │
│             │                    └─────────────────────┘
└─────────────┘
```

Each plugin is a separate process. The daemon discovers plugins at startup,
spawns them as child processes, and communicates with them through Unix domain
sockets located at `/var/run/nipart/sockets/plugin/<plugin_name>`.

## Plugin Trait

All plugins implement the `NipartPlugin` trait, defined in
`src/lib/plugin/plugin_trait.rs`:

```rust
pub trait NipartPlugin: Send + Sync + Sized + 'static {
    const PLUGIN_NAME: &'static str;

    fn init() -> impl Future<Output = Result<Self, NipartError>> + Send;
    fn plugin_info(plugin: &Arc<Self>) -> impl Future<Output = Result<NipartPluginInfo, NipartError>> + Send;
    fn query_network_state(...) -> impl Future<Output = Result<NetworkState, NipartError>> + Send;
    fn apply_network_state(...) -> impl Future<Output = Result<(), NipartError>> + Send;
    fn wifi_scan(...) -> impl Future<Output = Result<Vec<WifiScanResult>, NipartError>> + Send;
    fn quit(plugin: &Arc<Self>) -> impl Future<Output = ()> + Send;
}
```

### Required Methods

| Method | Description |
|--------|-------------|
| `PLUGIN_NAME` | Constant string identifying the plugin (e.g., `"wifi"`, `"ovs"`) |
| `init()` | Plugin initialization. Called once when the plugin process starts |
| `plugin_info()` | Returns `NipartPluginInfo` containing the plugin name, version, and supported interface types |

### Optional Methods (with default "not supported" implementations)

| Method | Description |
|--------|-------------|
| `query_network_state()` | Query the network state managed by this plugin. Receives the current kernel state (queried via netlink) for reference |
| `apply_network_state()` | Apply desired network state to the managed subsystem |
| `wifi_scan()` | Perform an active WiFi scan and return discovered networks |
| `quit()` | Clean shutdown. Default implementation calls `std::process::exit(0)` |

The default `run()` method provided by the trait handles the entire plugin
lifecycle: it calls `init()`, creates a Unix socket listener, then loops
accepting connections from the daemon and spawning a tokio task for each
connection.

## IPC Protocol

Communication between daemon and plugin uses a structured command/response
protocol over Unix domain sockets. Each message is serialized via serde.

### Commands (Daemon → Plugin)

The `NipartPluginCmd` enum defines all commands the daemon can send:

| Command | Payload | Expected Response |
|---------|---------|-------------------|
| `QueryPluginInfo` | None | `NipartPluginInfo` |
| `QueryNetworkState` | `(NipartQueryOption, NetworkState)` | `NetworkState` |
| `ApplyNetworkState` | `(NetworkState, NipartApplyOption)` | `()` |
| `WifiScan` | `NipartWifiScanOption` | `Vec<WifiScanResult>` |
| `Quit` | None | None (process exits) |

### Plugin Info

The `NipartPluginInfo` structure identifies what a plugin provides:

```rust
pub struct NipartPluginInfo {
    pub name: String,              // Plugin name, e.g. "wifi"
    pub version: String,           // Plugin version, e.g. "0.1.0"
    pub iface_types: Vec<InterfaceType>,  // Interface types this plugin manages
}
```

The `iface_types` field is critical — it tells the daemon which interface types
this plugin handles. When applying state, the daemon filters interfaces by
`iface_type()` and routes only matching interfaces to the appropriate plugin.

### Logging from Plugins

Plugins can send log messages back to the daemon via the connection object
(`conn.log_trace()`, `conn.log_debug()`, etc.), allowing plugin-specific
diagnostics to appear in the daemon's log output.

## Plugin Discovery and Lifecycle

### Discovery

At startup, the daemon's plugin worker scans the directory containing the
daemon binary for executable files whose names start with `nipart-plugin-`.
For example, if the daemon is at `/usr/bin/nipart`, it looks for
`/usr/bin/nipart-plugin-*`.

### Startup

1. Each discovered plugin binary is spawned as a child process
2. The plugin calls `init()` and starts listening on its Unix socket at
   `/var/run/nipart/sockets/plugin/<PLUGIN_NAME>`
3. The daemon retries connecting to each plugin socket (up to 50 times,
   with 200ms intervals: ~10 seconds total timeout)
4. On successful connection, the daemon sends `QueryPluginInfo` to register
   the plugin and learn its capabilities

### Shutdown

When the daemon shuts down:
- Each plugin child process receives `SIGKILL`
- Plugin Unix sockets are cleaned up

### Plugin Process Naming

Plugin binaries follow the naming convention `nipart-plugin-<name>`:

- `nipart-plugin-wifi`
- `nipart-plugin-8021x`
- `nipart-plugin-ovs`
- `nipart-plugin-demo` (ignored by the daemon in normal operation)

## Daemon-Side Plugin Management

The daemon's plugin subsystem lives in `src/daemon/plugin/` and consists of
three components:

### `NipartPluginWorker`

Implements the `TaskWorker` trait. This is the main plugin orchestrator that:
- Discovers and spawns plugin processes
- Maintains a registry of connected plugins (`HashMap<String, NipartDaemonPlugin>`)
- Tracks all supported interface types across plugins
- Dispatches `QueryNetworkState`, `ApplyNetworkState`, and `WifiScan` commands
  to the appropriate plugins
- Handles plugin failures gracefully (logs errors, does not crash the daemon)

### `NipartPluginManager`

A thin wrapper around `TaskManager<NipartPluginCmd, NipartPluginReply>` that
provides a clean async API for the rest of the daemon to interact with plugins.

### `NipartDaemonPlugin`

Represents a single connected plugin from the daemon's perspective. Holds the
plugin's name, info, and socket path. Provides convenience methods
(`query_network_state`, `apply_network_state`, `wifi_scan`) that create an IPC
client, send the command, and return the response.

### Interface Type Routing

When applying state, each plugin only receives the interfaces whose type
matches its declared `iface_types`. For example, `nipart-plugin-wifi` only
receives interfaces of type `WifiCfg` or `WifiPhy`. If no plugin declares
support for an interface type in the desired state, the daemon returns a
`DependencyError`.

## Implementing a Plugin

### Project Structure

A plugin is a standalone Rust binary crate under `src/plugin-<name>/`:

```
src/plugin-wifi/
├── Cargo.toml
├── main.rs        # Entry point: calls NipartPlugin::run()
├── plugin.rs      # NipartPlugin trait implementation
├── apply.rs       # Apply logic
├── query.rs       # Query logic
├── scan.rs        # WiFi scan logic
└── ...
```

### Minimal Plugin Example

```rust
use nipart::{NipartPlugin, NipartPluginInfo, NipartError, NetworkState,
    NipartQueryOption, NipartApplyOption, NipartIpcConnection};
use std::sync::Arc;

struct MyPlugin;

impl NipartPlugin for MyPlugin {
    const PLUGIN_NAME: &'static str = "my-plugin";

    async fn init() -> Result<Self, NipartError> {
        Ok(Self {})
    }

    async fn plugin_info(_plugin: &Arc<Self>) -> Result<NipartPluginInfo, NipartError> {
        Ok(NipartPluginInfo::new(
            "my-plugin".to_string(),
            "0.1.0".to_string(),
            vec![],
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), NipartError> {
    MyPlugin::run().await
}
```

### Cargo.toml Requirements

```toml
[package]
name = "nipart-plugin-my-plugin"
version = "0.1.0"
edition = "2024"

[dependencies]
nipart = { path = "../lib" }
tokio = { version = "1", features = ["full"] }
```

### Key Implementation Notes

1. **The plugin binary name must start with `nipart-plugin-`** for the daemon
   to discover it
2. **`PLUGIN_NAME` determines the socket path**: the daemon connects to
   `/var/run/nipart/sockets/plugin/<PLUGIN_NAME>`
3. **Interface type routing**: declare the interface types your plugin manages
   in `plugin_info()`. The daemon will only send interfaces of those types
4. **Connection handling**: each daemon connection spawns a separate tokio task;
   use `Arc<Self>` for shared plugin state
5. **Error handling**: return `NipartError` with appropriate `ErrorKind` on
   failure; the daemon logs plugin errors but continues operating
6. **Logging**: use `conn.log_trace()` / `conn.log_debug()` to send log
   messages to the daemon's log stream
7. **The demo plugin is automatically ignored** by the daemon — no special
   configuration is needed to exclude it
