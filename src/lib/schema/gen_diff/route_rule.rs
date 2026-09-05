// SPDX-License-Identifier: Apache-2.0

use crate::RouteRules;

impl RouteRules {
    pub(crate) fn gen_diff(&self, old: &Self) -> Self {
        let mut diff_rules = Vec::new();

        match (self.config.as_ref(), old.config.as_ref()) {
            (Some(new_rules), Some(old_rules)) => {
                for new_rule in new_rules {
                    if old_rules
                        .iter()
                        .all(|old_rule| !new_rule.is_match(old_rule))
                    {
                        diff_rules.push(new_rule.clone());
                    }
                }
            }
            (Some(new_rules), None) => {
                diff_rules = new_rules.clone();
            }
            (None, Some(old_rules)) => {
                diff_rules = old_rules.clone();
            }
            _ => (),
        }

        Self {
            config: Some(diff_rules),
            ..Default::default()
        }
    }
}
