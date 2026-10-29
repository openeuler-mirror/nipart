// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use futures_util::TryStreamExt;
use rtnetlink::packet_route::link::{LinkAttribute, LinkMessage};

use crate::{NipartError, netlink::map_rtnetlink_error};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct LinkIndexMap {
    by_index: HashMap<u32, String>,
    by_name: HashMap<String, u32>,
}

#[allow(dead_code)]
impl LinkIndexMap {
    fn insert(&mut self, index: u32, name: String) {
        self.by_index.insert(index, name.clone());
        self.by_name.insert(name, index);
    }

    pub(crate) fn name(&self, index: u32) -> Option<&str> {
        self.by_index.get(&index).map(String::as_str)
    }

    pub(crate) fn index(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }
}

pub(crate) fn index_map_from_messages<'a>(
    messages: impl IntoIterator<Item = &'a LinkMessage>,
) -> LinkIndexMap {
    let mut map = LinkIndexMap::default();
    for message in messages {
        let name = message.attributes.iter().find_map(|attribute| {
            if let LinkAttribute::IfName(name) = attribute {
                Some(name.to_string())
            } else {
                None
            }
        });
        if let Some(name) = name
            && !name.is_empty()
        {
            map.insert(message.header.index, name);
        }
    }
    map
}

#[allow(dead_code)]
pub(crate) async fn get_index_map(
    handle: &rtnetlink::Handle,
) -> Result<LinkIndexMap, NipartError> {
    let mut messages = handle.link().get().execute();
    let mut links = Vec::new();
    while let Some(message) = messages
        .try_next()
        .await
        .map_err(|e| map_rtnetlink_error("Failed to dump kernel links", e))?
    {
        links.push(message);
    }
    Ok(index_map_from_messages(links.iter()))
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::{
        AddressFamily,
        link::{LinkFlags, LinkLayerType, LinkMessage},
    };

    use super::index_map_from_messages;
    use crate::netlink::unit_tests::fixtures::link_message;

    #[test]
    fn test_index_map_from_messages() {
        let loopback =
            link_message(1, "lo", LinkLayerType::Loopback, LinkFlags::Up);
        let ethernet =
            link_message(2, "eth0", LinkLayerType::Ether, LinkFlags::Up);
        let mut unnamed = LinkMessage::default();
        unnamed.header.interface_family = AddressFamily::Unspec;
        unnamed.header.index = 3;

        let map = index_map_from_messages([&loopback, &ethernet, &unnamed]);
        assert_eq!(map.index("lo"), Some(1));
        assert_eq!(map.index("eth0"), Some(2));
        assert_eq!(map.name(1), Some("lo"));
        assert_eq!(map.name(2), Some("eth0"));
        assert_eq!(map.name(3), None);
        assert_eq!(map.index("missing"), None);
    }
}
