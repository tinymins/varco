//! The one authorized public key and the host key, kept in the user's config
//! directory. The on/off switch is deliberately not stored anywhere.
use anyhow::{Context, Result};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use std::fmt;
use std::path::{Path, PathBuf};

const HOST_KEY_FILE: &str = "ssh_host_ed25519_key";
const AUTHORIZED_KEY_FILE: &str = "authorized_key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Empty,
    PrivateKey,
    Invalid,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "请填写公钥",
            Self::PrivateKey => {
                "这是私钥，不能填在这里。私钥请留在你自己手里，这里填 .pub 文件的内容"
            }
            Self::Invalid => "公钥格式不正确，应为一行 ssh-ed25519 AAAA… 这样的内容",
        })
    }
}

impl std::error::Error for KeyError {}

/// Exactly one key in OpenSSH one-line form.
pub fn parse_public_key(text: &str) -> Result<PublicKey, KeyError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(KeyError::Empty);
    }
    if text.contains("PRIVATE KEY") {
        return Err(KeyError::PrivateKey);
    }
    if text.lines().count() != 1 {
        return Err(KeyError::Invalid);
    }
    PublicKey::from_openssh(text).map_err(|_| KeyError::Invalid)
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open_default() -> Result<Self> {
        let base = dirs::config_dir().context("no user config directory")?;
        Ok(Self::at(base.join("varco")))
    }

    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// Stays the same across runs, so clients' known_hosts keeps matching.
    pub fn load_or_create_host_key(&self) -> Result<PrivateKey> {
        let path = self.dir.join(HOST_KEY_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => PrivateKey::from_openssh(&text)
                .with_context(|| format!("parsing host key {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.ensure_dir()?;
                let key = generate_ed25519();
                let text = key
                    .to_openssh(LineEnding::LF)
                    .context("encoding host key")?;
                write_private(&path, text.as_bytes())
                    .with_context(|| format!("writing host key {}", path.display()))?;
                Ok(key)
            }
            Err(e) => Err(e).with_context(|| format!("reading host key {}", path.display())),
        }
    }

    pub fn load_authorized_key(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.dir.join(AUTHORIZED_KEY_FILE)).ok()?;
        Some(text.trim().to_owned())
    }

    pub fn save_authorized_key(&self, text: &str) -> Result<()> {
        // A pasted private key must never reach the disk.
        parse_public_key(text)?;
        self.ensure_dir()?;
        std::fs::write(
            self.dir.join(AUTHORIZED_KEY_FILE),
            format!("{}\n", text.trim()),
        )?;
        Ok(())
    }
}

fn generate_ed25519() -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(
        &crate::credential::generate_secret(),
    ))
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("varco-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Store::at(dir.clone()), dir)
    }

    fn sample_public() -> String {
        generate_ed25519().public_key().to_openssh().unwrap()
    }

    #[test]
    fn accepts_a_public_key_with_comment_and_whitespace() {
        let line = format!("  {} someone@host \n", sample_public());
        assert!(parse_public_key(&line).is_ok());
    }

    #[test]
    fn rejects_empty_garbage_and_multiple_keys() {
        assert_eq!(parse_public_key("  ").unwrap_err(), KeyError::Empty);
        assert_eq!(parse_public_key("hello").unwrap_err(), KeyError::Invalid);
        let two = format!("{}\n{}", sample_public(), sample_public());
        assert_eq!(parse_public_key(&two).unwrap_err(), KeyError::Invalid);
    }

    #[test]
    fn a_pasted_private_key_is_recognized_and_never_saved() {
        let key = generate_ed25519();
        let pem = key.to_openssh(LineEnding::LF).unwrap().to_string();
        assert_eq!(parse_public_key(&pem).unwrap_err(), KeyError::PrivateKey);
        let (store, dir) = temp_store("private");
        assert!(store.save_authorized_key(&pem).is_err());
        assert!(!dir.join(AUTHORIZED_KEY_FILE).exists());
    }

    #[test]
    fn authorized_key_round_trips() {
        let (store, dir) = temp_store("authorized");
        assert_eq!(store.load_authorized_key(), None);
        let line = sample_public();
        store.save_authorized_key(&line).unwrap();
        assert_eq!(store.load_authorized_key().as_deref(), Some(line.as_str()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn host_key_is_stable_and_private() {
        let (store, dir) = temp_store("host");
        let first = store.load_or_create_host_key().unwrap();
        let second = store.load_or_create_host_key().unwrap();
        assert_eq!(
            fingerprint(first.public_key()),
            fingerprint(second.public_key())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join(HOST_KEY_FILE)), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
