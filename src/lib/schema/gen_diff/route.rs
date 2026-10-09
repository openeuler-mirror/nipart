// SPDX-License-Identifier: Apache-2.0

use crate::{MergedRoutes, Routes};

impl MergedRoutes {
    pub(crate) fn gen_diff(&self) -> Routes {
        Routes {
            config: if self.changed_routes.is_empty() {
                None
            } else {
                Some(self.changed_routes.clone())
            },
            ..Default::default()
        }
    }
}

impl Routes {
    pub(crate) fn gen_diff(&self, old: &Self) -> Self {
        let mut diff_routes = Vec::new();

        match (self.config.as_ref(), old.config.as_ref()) {
            (Some(new_routes), Some(old_routes)) => {
                for new_route in new_routes {
                    if old_routes
                        .iter()
                        .all(|old_route| !new_route.is_match(old_route))
                    {
                        diff_routes.push(new_route.clone());
                    }
                }
            }

            (Some(new_routes), None) => {
                diff_routes = new_routes.clone();
            }
            (None, Some(old_routes)) => {
                diff_routes = old_routes.clone();
            }
            _ => (),
        }

        Self {
            config: Some(diff_routes),
            ..Default::default()
        }
    }
}
