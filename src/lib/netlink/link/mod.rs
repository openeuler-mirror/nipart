// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
    AddressFamily,
    link::{LinkAttribute, LinkExtentMask, LinkMessage},
};

use crate::{NipartError, netlink::map_rtnetlink_error};

pub(crate) mod apply;
pub(crate) mod bond;
pub(crate) mod bridge;
pub(crate) mod ethtool;
pub(crate) mod macsec;
pub(crate) mod parse;
pub(crate) mod state;
pub(crate) mod vlan;
pub(crate) mod vrf;
pub(crate) mod vxlan;
pub(crate) mod wireguard;

pub(crate) use self::state::LinkState;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct LinkIndexMap {
    by_index: HashMap<u32, String>,
    by_name: HashMap<String, u32>,
}

#[allow(dead_code)]
impl LinkIndexMap {
    pub(crate) fn insert(&mut self, index: u32, name: String) {
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

pub(crate) async fn get_link_messages() -> Result<Vec<LinkMessage>, NipartError>
{
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| {
        super::map_io_error("Failed to create rtnetlink connection", e)
    })?;
    tokio::spawn(connection);
    let mut messages = handle.link().get().execute();
    let mut links = Vec::new();
    while let Some(message) = messages
        .try_next()
        .await
        .map_err(|e| map_rtnetlink_error("Failed to dump kernel links", e))?
    {
        links.push(message);
    }

    // Bridge VLAN information is only returned by a separate dump with the
    // bridge extent mask. Attach those attributes to the matching link
    // messages so a single message map can be parsed.
    let mut bridge_vlan_messages = handle
        .link()
        .get()
        .set_filter_mask(
            AddressFamily::Bridge,
            vec![LinkExtentMask::BrvlanCompressed],
        )
        .execute();
    let mut bridge_vlans: HashMap<u32, Vec<LinkAttribute>> = HashMap::new();
    while let Some(message) = bridge_vlan_messages
        .try_next()
        .await
        .map_err(|e| map_rtnetlink_error("Failed to dump bridge VLANs", e))?
    {
        let attributes: Vec<LinkAttribute> = message
            .attributes
            .into_iter()
            .filter(|attribute| {
                matches!(attribute, LinkAttribute::AfSpecBridge(_))
            })
            .collect();
        if !attributes.is_empty() {
            bridge_vlans.insert(message.header.index, attributes);
        }
    }
    for message in links.iter_mut() {
        if let Some(attributes) = bridge_vlans.remove(&message.header.index) {
            message.attributes.extend(attributes);
        }
    }
    Ok(links)
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

pub(crate) async fn get_iface_index_opt(
    handle: &rtnetlink::Handle,
    iface_name: &str,
) -> Result<Option<u32>, NipartError> {
    let mut messages = handle.link().get().match_name(iface_name).execute();
    match messages.try_next().await {
        Ok(Some(message)) => Ok(Some(message.header.index)),
        Ok(None) => Ok(None),
        // A single-link query returns ENODEV when the interface is gone,
        // which is not an error for the optional lookup.
        Err(error) if is_errno(&error, nix::errno::Errno::ENODEV) => Ok(None),
        Err(error) => Err(map_rtnetlink_error(
            "Failed to query interface index",
            error,
        )),
    }
}

fn is_errno(error: &rtnetlink::Error, errno: nix::errno::Errno) -> bool {
    matches!(error, rtnetlink::Error::NetlinkError(e)
        if e.raw_code() == -(errno as i32))
}

pub(crate) async fn get_iface_index(
    handle: &rtnetlink::Handle,
    iface_name: &str,
) -> Result<u32, NipartError> {
    get_iface_index_opt(handle, iface_name)
        .await?
        .ok_or_else(|| {
            NipartError::new(
                crate::ErrorKind::InvalidArgument,
                format!("Interface {iface_name} does not exist"),
            )
        })
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
