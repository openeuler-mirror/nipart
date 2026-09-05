// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Jan Vaclav <jvaclav@redhat.com>
//  * Íñigo Huguet <ihuguet@redhat.com>
//  * Fernando Fernandez Mancera <ffmancera@riseup.net>

use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
};

use serde::{Deserialize, Serialize};

use super::ip::{is_ipv6_addr, sanitize_ip_network};
use crate::{ErrorKind, JsonDisplay, NipartError};

const ROUTE_RULE_DEFAULT_PRIORITY: i64 = 30000;
const ROUTE_RULE_DEFAULT_ROUTE_TABLE_ID: u32 = 254;

#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonDisplay,
)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
/// Routing rules
pub struct RouteRules {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// When applying, `None` means preserve existing route rules.
    /// Nipart uses partial editing for route rules, which means desired
    /// route rules only append to existing instead of overriding.
    /// To delete a route rule, please set [RouteRuleEntry.state] to
    /// [RouteRuleState::Absent]. Any property set to `None` in an absent
    /// route rule means wildcard. For example, this YAML removes all route
    /// rules looking up route table 500:
    /// ```yaml
    /// ---
    /// route-rules:
    ///   config:
    ///     - state: absent
    ///       route-table: 500
    /// ```
    pub config: Option<Vec<RouteRuleEntry>>,
}

impl RouteRules {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether configured route rules is empty or undefined.
    pub fn is_empty(&self) -> bool {
        if let Some(rules) = self.config.as_ref() {
            rules.is_empty()
        } else {
            true
        }
    }

    pub(crate) fn validate(&self) -> Result<(), NipartError> {
        if let Some(rules) = self.config.as_ref() {
            for rule in rules {
                if let Some(ip_from) = rule.ip_from.as_deref()
                    && !ip_from.is_empty()
                {
                    sanitize_ip_network(ip_from)?;
                }
                if let Some(ip_to) = rule.ip_to.as_deref()
                    && !ip_to.is_empty()
                {
                    sanitize_ip_network(ip_to)?;
                }
                if !rule.is_absent() {
                    rule.validate()?;
                }
            }
        }
        Ok(())
    }

    /// Merge route rules into `self`, preserving the partial editing
    /// semantics: non-absent rules are added and absent rules remove the
    /// matching existing rules.
    pub(crate) fn merge(&self, new_rules: &Self) -> Result<Self, NipartError> {
        new_rules.validate()?;

        let Some(new_rules) = new_rules.config.as_ref() else {
            return Ok(self.clone());
        };

        let mut rule_set: HashSet<RouteRuleEntry> = HashSet::new();
        for new_rule in new_rules.iter().filter(|r| !r.is_absent()) {
            rule_set.insert(new_rule.clone());
        }
        if let Some(old_rules) = self.config.as_ref() {
            for old_rule in old_rules {
                if new_rules
                    .iter()
                    .any(|r| r.is_absent() && r.is_match(old_rule))
                {
                    continue;
                }
                rule_set.insert(old_rule.clone());
            }
        }

        let mut rules: Vec<RouteRuleEntry> = rule_set.into_iter().collect();
        rules.sort_unstable();
        Ok(RouteRules {
            config: Some(rules),
        })
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
#[derive(Default)]
pub enum RouteRuleState {
    /// Used for deleting a route rule.
    #[default]
    Absent,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AddressFamily {
    #[default]
    Ipv4,
    Ipv6,
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Ipv4 => "ipv4",
                Self::Ipv6 => "ipv6",
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub enum RouteRuleAction {
    Blackhole,
    Unreachable,
    Prohibit,
}

impl std::fmt::Display for RouteRuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Blackhole => "blackhole",
                Self::Unreachable => "unreachable",
                Self::Prohibit => "prohibit",
            }
        )
    }
}

impl From<RouteRuleAction> for u8 {
    fn from(v: RouteRuleAction) -> u8 {
        match v {
            RouteRuleAction::Blackhole => 6,
            RouteRuleAction::Unreachable => 7,
            RouteRuleAction::Prohibit => 8,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RouteRuleEntry {
    /// Indicate the address family of the route rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<AddressFamily>,
    /// Indicate this is a normal or absent route rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RouteRuleState>,
    /// Source prefix to match.
    /// Serialize and deserialize to/from `ip-from`.
    #[serde(skip_serializing_if = "Option::is_none", rename = "ip-from")]
    pub ip_from: Option<String>,
    /// Destination prefix to match.
    /// Serialize and deserialize to/from `ip-to`.
    #[serde(skip_serializing_if = "Option::is_none", rename = "ip-to")]
    pub ip_to: Option<String>,
    /// Priority of this route rule. Bigger number means lower priority.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_i64_or_string"
    )]
    pub priority: Option<i64>,
    /// The routing table ID to look up when the rule selector matches.
    /// Serialize and deserialize to/from `route-table`.
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "route-table",
        default,
        deserialize_with = "crate::deserializer::option_u32_or_string"
    )]
    pub table_id: Option<u32>,
    /// Firewall mark value to match.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_u32_or_string",
        serialize_with = "crate::serializer::option_u32_as_hex"
    )]
    pub fwmark: Option<u32>,
    /// Firewall mark mask to match.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_u32_or_string",
        serialize_with = "crate::serializer::option_u32_as_hex"
    )]
    pub fwmask: Option<u32>,
    /// Action performed for matching packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<RouteRuleAction>,
    /// Incoming interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iif: Option<String>,
    /// Prefix length to suppress.
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "suppress-prefix-length",
        alias = "suppress_prefixlength"
    )]
    pub suppress_prefix_length: Option<u32>,
}

impl RouteRuleEntry {
    /// Let the network backend choose the default priority.
    pub const USE_DEFAULT_PRIORITY: i64 = -1;
    /// Use the main route table 254.
    pub const USE_DEFAULT_ROUTE_TABLE: u32 = 0;
    /// Default route table main(254).
    pub const DEFAULT_ROUTE_TABLE_ID: u32 = ROUTE_RULE_DEFAULT_ROUTE_TABLE_ID;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_absent(&self) -> bool {
        matches!(self.state, Some(RouteRuleState::Absent))
    }

    pub(crate) fn is_ipv6(&self) -> bool {
        self.family == Some(AddressFamily::Ipv6)
            || self.ip_from.as_ref().map(|i| is_ipv6_addr(i.as_str()))
                == Some(true)
            || self.ip_to.as_ref().map(|i| is_ipv6_addr(i.as_str()))
                == Some(true)
    }

    fn validate(&self) -> Result<(), NipartError> {
        if self.ip_from.is_none()
            && self.ip_to.is_none()
            && self.family.is_none()
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Neither ip-from, ip-to nor family is defined '{self}'"
                ),
            ));
        }
        if let Some(family) = self.family {
            if let Some(ip_from) = self.ip_from.as_ref()
                && is_ipv6_addr(ip_from) != (family == AddressFamily::Ipv6)
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "The ip-from format mismatches with the family set \
                         '{self}'"
                    ),
                ));
            }
            if let Some(ip_to) = self.ip_to.as_ref()
                && is_ipv6_addr(ip_to) != (family == AddressFamily::Ipv6)
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "The ip-to format mismatches with the family set \
                         '{self}'"
                    ),
                ));
            }
        }
        self.validate_fwmark_and_fwmask()
    }

    fn validate_fwmark_and_fwmask(&self) -> Result<(), NipartError> {
        if self.fwmark.is_none() && self.fwmask.is_some() {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "fwmask is present but fwmark is not defined or is zero \
                     {self:?}"
                ),
            ));
        }
        Ok(())
    }

    /// Whether the desired route rule (self) matches with another.
    pub fn is_match(&self, other: &Self) -> bool {
        if let Some(ip_from) = self.ip_from.as_deref() {
            if !ip_from.is_empty() {
                let Some(ip_from) = canonical_ip_network(ip_from) else {
                    return false;
                };
                if other.ip_from != Some(ip_from) {
                    return false;
                }
            } else if other.ip_from.as_deref().map(|s| s.is_empty())
                == Some(false)
            {
                // `ip-from: ""` matches rules without an `ip-from`.
                return false;
            }
        }
        if let Some(ip_to) = self.ip_to.as_deref() {
            if !ip_to.is_empty() {
                let Some(ip_to) = canonical_ip_network(ip_to) else {
                    return false;
                };
                if other.ip_to != Some(ip_to) {
                    return false;
                }
            } else if other.ip_to.as_deref().map(|s| s.is_empty())
                == Some(false)
            {
                return false;
            }
        }
        if self.family.is_some()
            && other.family.is_some()
            && self.family != other.family
        {
            return false;
        }
        if self.priority.is_some()
            && self.priority != Some(Self::USE_DEFAULT_PRIORITY)
            && self.priority != other.priority
            && !(self.priority == Some(0) && other.priority.is_none())
        {
            return false;
        }
        if self.table_id.is_some()
            && self.table_id != Some(Self::USE_DEFAULT_ROUTE_TABLE)
            && self.table_id != other.table_id
        {
            return false;
        }
        if self.fwmark.is_some()
            && self.fwmark.unwrap_or(0) != other.fwmark.unwrap_or(0)
        {
            return false;
        }
        if self.fwmask.is_some()
            && self.fwmask.unwrap_or(0) != other.fwmask.unwrap_or(0)
        {
            return false;
        }
        if self.iif.is_some() && self.iif != other.iif {
            return false;
        }
        if self.action.is_some() && self.action != other.action {
            return false;
        }
        if self.suppress_prefix_length.is_some()
            && self.suppress_prefix_length != other.suppress_prefix_length
        {
            return false;
        }
        true
    }

    fn sort_key(
        &self,
    ) -> (bool, bool, u32, &str, &str, i64, u32, u32, u8, u32, &str) {
        (
            !self.is_absent(),
            if let Some(ip_from) = self.ip_from.as_ref() {
                !is_ipv6_addr(ip_from)
            } else if let Some(ip_to) = self.ip_to.as_ref() {
                !is_ipv6_addr(ip_to)
            } else if let Some(family) = self.family.as_ref() {
                *family == AddressFamily::Ipv4
            } else {
                true
            },
            self.table_id.unwrap_or(Self::USE_DEFAULT_ROUTE_TABLE),
            self.ip_from.as_deref().unwrap_or(""),
            self.ip_to.as_deref().unwrap_or(""),
            self.priority.unwrap_or(Self::USE_DEFAULT_PRIORITY),
            self.fwmark.unwrap_or(0),
            self.fwmask.unwrap_or(0),
            self.action.map(u8::from).unwrap_or(0),
            self.suppress_prefix_length.unwrap_or_default(),
            self.iif.as_deref().unwrap_or(""),
        )
    }

    pub(crate) fn sanitize(&mut self) -> Result<(), NipartError> {
        if let Some(ip_from) = self.ip_from.as_ref() {
            if ip_from.is_empty() {
                self.ip_from = None;
            } else {
                let new_ip_from = sanitize_ip_network(ip_from)?;
                if self.family.is_none() {
                    self.family = Some(if is_ipv6_addr(&new_ip_from) {
                        AddressFamily::Ipv6
                    } else {
                        AddressFamily::Ipv4
                    });
                }
                if ip_from != &new_ip_from {
                    log::warn!(
                        "Route rule ip-from {ip_from} sanitized to \
                         {new_ip_from}"
                    );
                    self.ip_from = Some(new_ip_from);
                }
            }
        }
        if let Some(ip_to) = self.ip_to.as_ref() {
            if ip_to.is_empty() {
                self.ip_to = None;
            } else {
                let new_ip_to = sanitize_ip_network(ip_to)?;
                if self.family.is_none() {
                    self.family = Some(if is_ipv6_addr(&new_ip_to) {
                        AddressFamily::Ipv6
                    } else {
                        AddressFamily::Ipv4
                    });
                }
                if ip_to != &new_ip_to {
                    log::warn!(
                        "Route rule ip-to {ip_to} sanitized to {new_ip_to}"
                    );
                    self.ip_to = Some(new_ip_to);
                }
            }
        }
        self.validate()?;

        if self.action.is_none() && self.table_id.is_none() {
            log::info!(
                "Route rule {self} has no action or route-table defined, \
                 using default route table {ROUTE_RULE_DEFAULT_ROUTE_TABLE_ID}"
            );
            self.table_id = Some(ROUTE_RULE_DEFAULT_ROUTE_TABLE_ID);
        }
        Ok(())
    }
}

fn canonical_ip_network(ip_net: &str) -> Option<String> {
    match sanitize_ip_network(ip_net) {
        Ok(network) => Some(network),
        Err(e) => {
            log::debug!("Failed to canonicalize route rule network: {e}");
            None
        }
    }
}

// For Vec::dedup()
impl PartialEq for RouteRuleEntry {
    fn eq(&self, other: &Self) -> bool {
        self.sort_key() == other.sort_key()
    }
}

// For Vec::sort_unstable()
impl Ord for RouteRuleEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

// For ord
impl Eq for RouteRuleEntry {}

// For ord
impl PartialOrd for RouteRuleEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for RouteRuleEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sort_key().hash(state);
    }
}

impl std::fmt::Display for RouteRuleEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut props = Vec::new();
        if self.is_absent() {
            props.push("state: absent".to_string());
        }
        if let Some(family) = self.family.as_ref() {
            props.push(format!("family: {family}"));
        }
        if let Some(ip_from) = self.ip_from.as_ref() {
            props.push(format!("ip-from: {ip_from}"));
        }
        if let Some(ip_to) = self.ip_to.as_ref() {
            props.push(format!("ip-to: {ip_to}"));
        }
        if let Some(priority) = self.priority.as_ref() {
            props.push(format!("priority: {priority}"));
        }
        if let Some(table_id) = self.table_id.as_ref() {
            props.push(format!("route-table: {table_id}"));
        }
        if let Some(fwmask) = self.fwmask.as_ref() {
            props.push(format!("fwmask: {fwmask:#x}"));
        }
        if let Some(fwmark) = self.fwmark.as_ref() {
            props.push(format!("fwmark: {fwmark:#x}"));
        }
        if let Some(iif) = self.iif.as_ref() {
            props.push(format!("iif: {iif}"));
        }
        if let Some(action) = self.action.as_ref() {
            props.push(format!("action: {action}"));
        }
        if let Some(prefix_length) = self.suppress_prefix_length.as_ref() {
            props.push(format!("suppress-prefix-length: {prefix_length}"));
        }
        write!(f, "{}", props.join(" "))
    }
}

/// Assign proper priority to rules without an explicit one.
pub(crate) fn set_auto_priority(
    for_apply: &mut [RouteRuleEntry],
    merged: &[RouteRuleEntry],
) {
    let mut max_priority = merged
        .iter()
        .map(|r| r.priority.unwrap_or_default())
        .max()
        .unwrap_or_default();
    if max_priority < ROUTE_RULE_DEFAULT_PRIORITY - 1 {
        max_priority = ROUTE_RULE_DEFAULT_PRIORITY - 1;
    }

    for rule in for_apply.iter_mut().filter(|r| {
        !r.is_absent()
            && (r.priority.is_none()
                || r.priority == Some(RouteRuleEntry::USE_DEFAULT_PRIORITY))
    }) {
        let cur_priority =
            merged.iter().find_map(|cur_rule| match cur_rule.priority {
                Some(RouteRuleEntry::USE_DEFAULT_PRIORITY) => None,
                Some(priority) => rule.is_match(cur_rule).then_some(priority),
                None => None,
            });
        if let Some(priority) = cur_priority {
            rule.priority = Some(priority);
        } else {
            max_priority += 1;
            rule.priority = Some(max_priority);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_from_yaml(yaml: &str) -> RouteRuleEntry {
        rmsd_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn test_route_rule_sanitize_single_host_adds_prefix_length() {
        let mut rule = rule_from_yaml(
            r#"
            ip-from: 203.0.113.1
            ip-to: 192.0.2.0/24
            route-table: 254
            "#,
        );
        rule.sanitize().unwrap();
        assert_eq!(rule.ip_from.as_deref(), Some("203.0.113.1/32"));
        assert_eq!(rule.family, Some(AddressFamily::Ipv4));
    }

    #[test]
    fn test_route_rule_absent_wildcard_matches_table() {
        let absent = rule_from_yaml(
            r#"
            state: absent
            route-table: 500
            "#,
        );
        let current = rule_from_yaml(
            r#"
            ip-from: 203.0.113.0/24
            route-table: 500
            priority: 1000
            "#,
        );
        assert!(absent.is_match(&current));
        assert!(!absent.is_match(&rule_from_yaml(
            r#"
            route-table: 501
            "#,
        )));
    }

    #[test]
    fn test_route_rule_fwmask_without_fwmark_rejected() {
        let mut rule = rule_from_yaml(
            r#"
            ip-from: 203.0.113.0/24
            route-table: 500
            fwmask: 0x10
            "#,
        );
        assert!(rule.sanitize().is_err());
    }

    #[test]
    fn test_route_rule_default_route_table() {
        let mut rule = rule_from_yaml(
            r#"
            ip-from: 203.0.113.1/32
            "#,
        );
        rule.sanitize().unwrap();
        assert_eq!(rule.table_id, Some(254));
    }

    #[test]
    fn test_route_rule_merge_is_partial() {
        let old: RouteRules = rmsd_yaml::from_str(
            r#"
            config:
              - ip-from: 203.0.113.0/24
                route-table: 500
              - ip-from: 198.51.100.0/24
                route-table: 500
            "#,
        )
        .unwrap();
        let new: RouteRules = rmsd_yaml::from_str(
            r#"
            config:
              - state: absent
                route-table: 500
                ip-from: 198.51.100.0/24
              - ip-from: 192.0.2.0/24
                route-table: 600
            "#,
        )
        .unwrap();

        let merged = old.merge(&new).unwrap();
        let rules = merged.config.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(
            rules
                .iter()
                .any(|r| r.ip_from.as_deref() == Some("203.0.113.0/24"))
        );
        assert!(
            rules
                .iter()
                .any(|r| r.ip_from.as_deref() == Some("192.0.2.0/24"))
        );
    }
}
