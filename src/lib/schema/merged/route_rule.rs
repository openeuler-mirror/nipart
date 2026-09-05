// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Jan Vaclav <jvaclav@redhat.com>
//  * Íñigo Huguet <ihuguet@redhat.com>
//  * Fernando Fernandez Mancera <ffmancera@riseup.net>

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::super::route_rule::set_auto_priority;
use crate::{
    ErrorKind, JsonDisplay, NipartError, RouteRuleEntry, RouteRuleState,
    RouteRules,
};

#[derive(
    Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct MergedRouteRules {
    pub desired: RouteRules,
    pub current: RouteRules,
    // The `changed_rules` holds two kinds of route rule:
    //  * Desired new route rules
    //  * Current route rules marked as absent
    pub changed_rules: Vec<RouteRuleEntry>,
    #[serde(default)]
    pub(crate) for_save: RouteRules,
}

impl MergedRouteRules {
    pub fn new(
        desired: RouteRules,
        current: RouteRules,
        saved: Option<RouteRules>,
    ) -> Result<Self, NipartError> {
        desired.validate()?;
        current.validate()?;

        let mut changed_rules: HashSet<RouteRuleEntry> = HashSet::new();
        let mut desired_rules: Vec<RouteRuleEntry> = Vec::new();
        let mut desired_absent_rules: Vec<&RouteRuleEntry> = Vec::new();
        if let Some(rules) = desired.config.as_ref() {
            for rule in rules {
                if rule.is_absent() {
                    desired_absent_rules.push(rule);
                } else {
                    let mut new_rule = rule.clone();
                    new_rule.sanitize()?;
                    desired_rules.push(new_rule);
                }
            }
        }

        let mut current_rules: Vec<RouteRuleEntry> = Vec::new();
        if let Some(rules) = current.config.as_ref() {
            for rule in rules {
                current_rules.push(rule.clone());
                if desired_absent_rules
                    .as_slice()
                    .iter()
                    .any(|absent_rule| absent_rule.is_match(rule))
                {
                    let mut absent_rule = rule.clone();
                    absent_rule.state = Some(RouteRuleState::Absent);
                    absent_rule.sanitize()?;
                    changed_rules.insert(absent_rule);
                }
            }
        }

        for desired_rule in &desired_rules {
            if !current_rule_matches(&current_rules, desired_rule) {
                changed_rules.insert(desired_rule.clone());
            }
        }

        let mut changed_rules: Vec<RouteRuleEntry> =
            changed_rules.into_iter().collect();
        changed_rules.sort_unstable();
        set_auto_priority(&mut changed_rules, &current_rules);

        let for_save =
            gen_route_rules_for_save(&desired, saved.as_ref(), &desired_rules)?;

        Ok(Self {
            desired,
            current,
            changed_rules,
            for_save,
        })
    }

    pub(crate) fn is_changed(&self) -> bool {
        !self.changed_rules.is_empty()
    }

    pub(crate) fn gen_state_for_apply(&self) -> RouteRules {
        RouteRules {
            config: if self.changed_rules.is_empty() {
                None
            } else {
                Some(self.changed_rules.clone())
            },
        }
    }

    pub(crate) fn gen_state_for_save(&self) -> RouteRules {
        RouteRules {
            config: self.for_save.config.clone(),
        }
    }

    pub(crate) fn gen_diff(&self) -> RouteRules {
        self.gen_state_for_apply()
    }

    pub(crate) fn generate_revert(&self) -> Result<RouteRules, NipartError> {
        let mut revert_rules: Vec<RouteRuleEntry> = Vec::new();
        let empty_vec: Vec<RouteRuleEntry> = Vec::new();
        let current_rules = self.current.config.as_ref().unwrap_or(&empty_vec);

        for changed_rule in self.changed_rules.iter() {
            if changed_rule.is_absent() {
                for cur_rule in current_rules {
                    if changed_rule.is_match(cur_rule) {
                        revert_rules.push(cur_rule.clone());
                    }
                }
            } else {
                let mut revert_rule = changed_rule.clone();
                revert_rule.state = Some(RouteRuleState::Absent);
                revert_rules.push(revert_rule);
            }
        }

        revert_rules.sort_unstable();
        revert_rules.dedup();
        Ok(RouteRules {
            config: if revert_rules.is_empty() {
                None
            } else {
                Some(revert_rules)
            },
        })
    }

    pub(crate) fn verify(
        &self,
        current: &RouteRules,
    ) -> Result<(), NipartError> {
        if let Some(rules) = self.desired.config.as_ref() {
            for rule in rules.iter().filter(|rule| !rule.is_absent()) {
                let mut desired_rule = rule.clone();
                desired_rule.sanitize()?;
                if !current_rule_matches(
                    current.config.as_deref().unwrap_or_default(),
                    &desired_rule,
                ) {
                    return Err(NipartError::new(
                        ErrorKind::VerificationError,
                        format!(
                            "Desired route rule {desired_rule} not found \
                             after apply"
                        ),
                    ));
                }
            }
        }

        for absent_rule in
            self.changed_rules.iter().filter(|rule| rule.is_absent())
        {
            if current.config.as_ref().is_some_and(|rules| {
                rules.iter().any(|r| absent_rule.is_match(r))
            }) {
                return Err(NipartError::new(
                    ErrorKind::VerificationError,
                    format!(
                        "Desired absent route rule {absent_rule} still found \
                         after apply"
                    ),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn remove_rules_to_ignored_ifaces(
        &mut self,
        ignored_ifaces: &[&str],
    ) {
        let retains_rule = |rule: &RouteRuleEntry| {
            rule.iif
                .as_ref()
                .is_none_or(|iif| !ignored_ifaces.contains(&iif.as_str()))
        };
        if let Some(rules) = self.desired.config.as_mut() {
            rules.retain(retains_rule);
        }
        if let Some(rules) = self.for_save.config.as_mut() {
            rules.retain(retains_rule);
        }
        self.changed_rules.retain(retains_rule);
    }
}

fn current_rule_matches(
    current_rules: &[RouteRuleEntry],
    rule: &RouteRuleEntry,
) -> bool {
    current_rules.iter().any(|cur_rule| rule.is_match(cur_rule))
}

/// Compute the route rules to persist: the desired non-absent rules plus
/// every previously saved route rule that survives this apply.
fn gen_route_rules_for_save(
    desired: &RouteRules,
    saved: Option<&RouteRules>,
    desired_rules: &[RouteRuleEntry],
) -> Result<RouteRules, NipartError> {
    let mut rules: HashSet<RouteRuleEntry> = HashSet::new();
    for new_rule in desired_rules {
        rules.insert(new_rule.clone());
    }
    if let Some(saved) = saved
        && let Some(saved_rules) = saved.config.as_ref()
    {
        for saved_rule in saved_rules.iter().filter(|r| !r.is_absent()) {
            let mut new_saved_rule = saved_rule.clone();
            new_saved_rule.sanitize()?;
            let removed =
                desired.config.as_ref().is_some_and(|desired_rules| {
                    desired_rules.iter().any(|desired_rule| {
                        desired_rule.is_absent()
                            && desired_rule.is_match(&new_saved_rule)
                    })
                });
            if !removed {
                rules.insert(new_saved_rule);
            }
        }
    }

    let mut rules: Vec<RouteRuleEntry> = rules.into_iter().collect();
    rules.sort_unstable();
    Ok(RouteRules {
        config: if rules.is_empty() { None } else { Some(rules) },
    })
}
