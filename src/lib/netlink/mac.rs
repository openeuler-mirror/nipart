// SPDX-License-Identifier: Apache-2.0

use crate::{ErrorKind, NipartError};

#[allow(dead_code)]
pub(crate) fn format_mac_address(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    Some(
        data.iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<String>>()
            .join(":"),
    )
}

#[allow(dead_code)]
pub(crate) fn parse_mac_address(mac: &str) -> Result<Vec<u8>, NipartError> {
    let hex: String = mac.chars().filter(|c| *c != ':' && *c != '-').collect();
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Invalid MAC address '{mac}'"),
        ));
    }
    let mut data = Vec::with_capacity(hex.len() / 2);
    for chunk_start in (0..hex.len()).step_by(2) {
        let chunk = &hex[chunk_start..chunk_start + 2];
        let byte = u8::from_str_radix(chunk, 16).map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid MAC address '{mac}': {e}"),
            )
        })?;
        data.push(byte);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::{format_mac_address, parse_mac_address};

    #[test]
    fn test_format_mac_address() {
        assert_eq!(
            format_mac_address(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            Some("02:00:00:00:00:01".to_string())
        );
        assert_eq!(
            format_mac_address(&[
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]),
            Some(
                "02:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01"
                    .to_string()
            )
        );
        assert_eq!(format_mac_address(&[]), None);
    }

    #[test]
    fn test_parse_mac_address() {
        let expected = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(parse_mac_address("02:00:00:00:00:01").unwrap(), expected);
        assert_eq!(parse_mac_address("02-00-00-00-00-01").unwrap(), expected);
        assert_eq!(parse_mac_address("020000000001").unwrap(), expected);
        assert_eq!(
            parse_mac_address("02:00:00:00:00:0A").unwrap(),
            vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x0A]
        );
    }

    #[test]
    fn test_parse_mac_address_invalid_input() {
        assert!(parse_mac_address("").is_err());
        assert!(parse_mac_address("02:00:00:00:00:0").is_err());
        assert!(parse_mac_address("02:00:00:00:00:0g").is_err());
        assert!(parse_mac_address("not-a-mac").is_err());
    }

    #[test]
    fn test_mac_round_trip() {
        let raw = parse_mac_address("02:00:00:00:00:01").unwrap();
        assert_eq!(
            parse_mac_address(&format_mac_address(&raw).unwrap()).unwrap(),
            raw
        );
    }
}
