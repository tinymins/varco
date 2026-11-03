//! A stable name for this machine, so a console ban outlasts a restart of the
//! program. Uses the operating system's machine id: CPU details are the same on
//! every machine of a model, so banning by them would ban all of those too.
//!
//! Reads a value the system already keeps, so nothing is written, and the elevated
//! helper gets the same answer as the window that started it. The client reports
//! this itself: it identifies honest clients and proves nothing about others.
use sha2::{Digest, Sha256};

const HEX_LEN: usize = 64;

/// The raw id is hashed so the server never learns it. `None` if the system has none.
pub fn device_id() -> Option<String> {
    raw_machine_id().as_deref().and_then(from_raw)
}

fn from_raw(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let digest = Sha256::new()
        .chain_update("varco-device-v1:")
        .chain_update(raw.to_ascii_lowercase())
        .finalize();
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// What the server accepts: clients choose this text, and it reaches the console.
pub fn is_valid(id: &str) -> bool {
    id.len() == HEX_LEN && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(target_os = "linux")]
fn raw_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .find(|text| linux_id_is_usable(text))
}

/// systemd writes "uninitialized" on an image that has not booted yet.
#[cfg(any(target_os = "linux", test))]
fn linux_id_is_usable(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty() && text != "uninitialized"
}

#[cfg(target_os = "macos")]
fn raw_machine_id() -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    parse_ioreg(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(any(target_os = "macos", test))]
fn parse_ioreg(output: &str) -> Option<String> {
    let line = output.lines().find(|l| l.contains("\"IOPlatformUUID\""))?;
    let value = line.split('=').nth(1)?.trim().trim_matches('"');
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(windows)]
fn raw_machine_id() -> Option<String> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    };
    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() };
    let key = wide(r"SOFTWARE\Microsoft\Cryptography");
    let name = wide("MachineGuid");
    let mut buffer = [0u16; 128];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: both strings are NUL-terminated and outlive the call, and `size`
    // gives the buffer's real length in bytes, which the call does not exceed.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    String::from_utf16(&buffer[..len]).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn raw_machine_id() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_stable_valid_and_hide_the_raw_id() {
        let id = from_raw("  ABC-123\n").unwrap();
        assert_eq!(id, from_raw("abc-123").unwrap());
        assert_ne!(id, from_raw("abc-124").unwrap());
        assert!(is_valid(&id));
        assert!(!id.contains("abc"));
    }

    #[test]
    fn empty_ids_give_nothing() {
        assert_eq!(from_raw(" \n"), None);
    }

    #[test]
    fn this_machine_is_consistent() {
        assert_eq!(device_id(), device_id());
        if let Some(id) = device_id() {
            assert!(is_valid(&id));
        }
    }

    #[test]
    fn validity_is_strict() {
        let good = "a".repeat(HEX_LEN);
        assert!(is_valid(&good));
        for bad in [
            String::new(),
            "a".repeat(HEX_LEN - 1),
            "a".repeat(HEX_LEN + 1),
            "A".repeat(HEX_LEN),
            format!("<{}", "a".repeat(HEX_LEN - 1)),
        ] {
            assert!(!is_valid(&bad), "{bad}");
        }
    }

    #[test]
    fn ioreg_output_is_parsed() {
        let output = r#"+-o J316sAP  <class IOPlatformExpertDevice>
    {
      "IOPolledInterface" = "AppleSmartBattery"
      "IOPlatformUUID" = "12345678-ABCD-5678-ABCD-1234567890AB"
      "serial-number" = <00>
    }"#;
        assert_eq!(
            parse_ioreg(output).as_deref(),
            Some("12345678-ABCD-5678-ABCD-1234567890AB")
        );
        assert_eq!(parse_ioreg("nothing here"), None);
    }

    #[test]
    fn unbooted_linux_images_have_no_id() {
        assert!(linux_id_is_usable("0123abc\n"));
        assert!(!linux_id_is_usable("uninitialized\n"));
        assert!(!linux_id_is_usable("\n"));
    }
}
