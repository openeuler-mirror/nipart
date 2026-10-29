// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

pub(crate) const SYSFS_NET_CLASS: &str = "/sys/class/net";

pub(crate) fn sysfs_net_device_path(iface_name: &str) -> PathBuf {
    Path::new(SYSFS_NET_CLASS).join(iface_name).join("device")
}

#[allow(dead_code)]
pub(crate) fn iface_driver(iface_name: &str) -> Option<String> {
    driver_from_sysfs_device_path(&sysfs_net_device_path(iface_name))
}

#[allow(dead_code)]
pub(crate) fn iface_pci_address(iface_name: &str) -> Option<String> {
    pci_address_from_sysfs_device_path(&sysfs_net_device_path(iface_name))
}

#[allow(dead_code)]
fn driver_from_sysfs_device_path(device_path: &Path) -> Option<String> {
    driver_name_from_sysfs_path(&device_path.join("driver").read_link().ok()?)
}

#[allow(dead_code)]
fn pci_address_from_sysfs_device_path(device_path: &Path) -> Option<String> {
    let device_target = device_path.read_link().ok()?;
    format_pci_address(device_target.file_name()?.to_str()?)
}

fn driver_name_from_sysfs_path(driver_path: &Path) -> Option<String> {
    driver_path.file_name()?.to_str().map(str::to_string)
}

fn format_pci_address(device_name: &str) -> Option<String> {
    let items: Vec<&str> = device_name.split(':').collect();
    let (domain, bus, slot_function) = match items.as_slice() {
        [bus, slot_function] => (0u32, *bus, *slot_function),
        [domain, bus, slot_function] => {
            (u32::from_str_radix(domain, 16).ok()?, *bus, *slot_function)
        }
        _ => return None,
    };
    let bus = u8::from_str_radix(bus, 16).ok()?;
    let mut slot_function = slot_function.split('.');
    let slot = u8::from_str_radix(slot_function.next()?, 16).ok()?;
    let function = u8::from_str_radix(slot_function.next()?, 16).ok()?;
    if slot_function.next().is_some() {
        return None;
    }
    if domain > u16::MAX.into() {
        Some(format!("{domain:08x}:{bus:02x}:{slot:02x}.{function}"))
    } else {
        Some(format!("{domain:04x}:{bus:02x}:{slot:02x}.{function}"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        driver_name_from_sysfs_path, format_pci_address, sysfs_net_device_path,
    };

    #[test]
    fn test_sysfs_net_device_path() {
        assert_eq!(
            sysfs_net_device_path("eth0"),
            Path::new("/sys/class/net/eth0/device")
        );
    }

    #[test]
    fn test_driver_name_from_sysfs_path() {
        assert_eq!(
            driver_name_from_sysfs_path(Path::new(
                "/sys/bus/pci/drivers/e1000e"
            )),
            Some("e1000e".to_string())
        );
        assert_eq!(driver_name_from_sysfs_path(Path::new("/")), None);
    }

    #[test]
    fn test_format_pci_address() {
        assert_eq!(
            format_pci_address("0000:02:00.0"),
            Some("0000:02:00.0".to_string())
        );
        assert_eq!(
            format_pci_address("02:1f.6"),
            Some("0000:02:1f.6".to_string())
        );
        assert_eq!(
            format_pci_address("0a:09.7"),
            Some("0000:0a:09.7".to_string())
        );
        assert_eq!(format_pci_address("virtual"), None);
        assert_eq!(format_pci_address("0000:02:00"), None);
        assert_eq!(format_pci_address("0000:02:00.0.1"), None);
    }
}
