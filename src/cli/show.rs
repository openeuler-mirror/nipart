// SPDX-License-Identifier: Apache-2.0

use nipart::{
    DnsResolver, Interface, NetworkState, NipartClient, NipartInterface,
    NipartNoDaemon, NipartQueryOption, RouteEntry, Routes,
};

use crate::CliError;

pub(crate) struct CommandShow;

impl CommandShow {
    pub(crate) const CMD: &str = "show";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new("show")
            .alias("s")
            .about("Query network state")
            .arg(clap::Arg::new("IFNAME_OR_PROFILE").index(1).help(
                "Show specific interface or profile only. Use `dns` or \
                 `route` to show only that section",
            ))
            .arg(
                clap::Arg::new("IFACE")
                    .long("iface")
                    .value_name("IFNAME")
                    .conflicts_with("IFNAME_OR_PROFILE")
                    .help(
                        "Show specific interface or profile only, even when \
                         its name is `dns` or `route`",
                    ),
            )
            .arg(
                clap::Arg::new("NO_DAEMON")
                    .long("no-daemon")
                    .visible_alias("kernel")
                    .short('n')
                    .visible_short_alias('k')
                    .action(clap::ArgAction::SetTrue)
                    .help("Do not connect to nipart daemon"),
            )
            .arg(
                clap::Arg::new("SAVED")
                    .long("saved")
                    .short('s')
                    .action(clap::ArgAction::SetTrue)
                    .help("Show the daemon saved state only"),
            )
            .arg(
                clap::Arg::new("SHOW_SECRETS")
                    .long("show-secrets")
                    .action(clap::ArgAction::SetTrue)
                    .help("Show secrets(hide by default)"),
            )
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<(), CliError> {
        let mut net_state = if matches.get_flag("NO_DAEMON") {
            if matches.get_flag("SAVED") {
                return Err("--no-daemon or --kernel cannot be used with \
                            --saved argument"
                    .into());
            }
            NipartNoDaemon::query_network_state(Default::default()).await?
        } else {
            let mut cli = NipartClient::new().await?;
            let mut opt = if matches.get_flag("SAVED") {
                NipartQueryOption::saved()
            } else {
                NipartQueryOption::running_and_saved()
            };
            if matches.get_flag("SHOW_SECRETS") {
                opt = opt.include_secrets(true);
            }
            cli.query_network_state(opt).await?
        };
        let selection = ShowSelection::from_matches(matches);

        if !matches.get_flag("SHOW_SECRETS") {
            net_state.hide_secrets();
        }

        let output = match selection {
            ShowSelection::All => rmsd_yaml::to_string(&net_state)?,
            ShowSelection::Iface(name) => {
                rmsd_yaml::to_string(&filter_net_state(&net_state, &name))?
            }
            ShowSelection::Section(section) => {
                section_to_yaml(&net_state, section)?
            }
        };
        println!("{output}");

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ShowSelection {
    All,
    Iface(String),
    Section(ShowSection),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ShowSection {
    Dns,
    Route,
}

impl ShowSelection {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        if let Some(iface) = matches.get_one::<String>("IFACE") {
            return Self::Iface(iface.clone());
        }
        match matches.get_one::<String>("IFNAME_OR_PROFILE") {
            Some(name) if name == "dns" => Self::Section(ShowSection::Dns),
            Some(name) if name == "route" => Self::Section(ShowSection::Route),
            Some(name) => Self::Iface(name.clone()),
            None => Self::All,
        }
    }
}

/// Serialize only the requested top-level section, keeping the output
/// reusable as an apply input.
fn section_to_yaml(
    net_state: &NetworkState,
    section: ShowSection,
) -> Result<String, CliError> {
    match section {
        ShowSection::Dns => Ok(rmsd_yaml::to_string(&DnsSection {
            dns_resolver: &net_state.dns_resolver,
        })?),
        ShowSection::Route => Ok(rmsd_yaml::to_string(&RoutesSection {
            routes: &net_state.routes,
        })?),
    }
}

#[derive(serde::Serialize)]
struct DnsSection<'a> {
    #[serde(rename = "dns-resolver")]
    dns_resolver: &'a DnsResolver,
}

#[derive(serde::Serialize)]
struct RoutesSection<'a> {
    routes: &'a Routes,
}

fn filter_net_state(net_state: &NetworkState, name: &str) -> NetworkState {
    let mut ret = NetworkState::new();
    let mut matched_ifaces: Vec<&Interface> = Vec::new();
    for iface in net_state.ifaces.iter() {
        if iface_matches_name(iface, name) {
            matched_ifaces.push(iface);
            ret.ifaces.push(iface.clone());
        }
    }
    ret.routes.running = filter_routes(
        net_state.routes.running.as_deref(),
        name,
        &matched_ifaces,
    );
    ret.routes.config = filter_routes(
        net_state.routes.config.as_deref(),
        name,
        &matched_ifaces,
    );
    ret
}

fn iface_matches_name(iface: &Interface, name: &str) -> bool {
    iface.name() == name
        || iface.kernel_iface_name() == name
        || iface.base_iface().profile_name.as_deref() == Some(name)
}

/// Keep only route entries whose next hop interface matches `name` or one of
/// the matched interfaces. Returns `None` when no route remains so the YAML
/// output stays clean.
fn filter_routes(
    routes: Option<&[RouteEntry]>,
    name: &str,
    matched_ifaces: &[&Interface],
) -> Option<Vec<RouteEntry>> {
    let filtered: Vec<RouteEntry> = routes
        .map(|rts| {
            rts.iter()
                .filter(|rt| {
                    route_matches_name(rt, name)
                        || matched_ifaces
                            .iter()
                            .any(|iface| route_matches_iface(rt, iface))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if filtered.is_empty() {
        None
    } else {
        Some(filtered)
    }
}

fn route_matches_name(rt: &RouteEntry, name: &str) -> bool {
    rt.next_hop_iface.as_deref() == Some(name)
}

fn route_matches_iface(rt: &RouteEntry, iface: &Interface) -> bool {
    let Some(next_hop_iface) = rt.next_hop_iface.as_deref() else {
        return false;
    };
    next_hop_iface == iface.kernel_iface_name()
        || next_hop_iface == iface.name()
        || iface.base_iface().profile_name.as_deref() == Some(next_hop_iface)
}

#[cfg(test)]
#[path = "unit_tests/show.rs"]
mod tests;
