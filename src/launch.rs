//! What the client should do on start, for packages that need no typing: settings
//! come from the command line, the environment, and a file beside the executable.
use crate::core::error::FailReason;
use crate::credential::Credential;
use serde::Deserialize;
use std::path::{Path, PathBuf};

// No `Debug`: these hold the Code, whose secret must never reach a log.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub code: Option<String>,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub ssh_pubkey: Option<String>,
    pub ssh_only: Option<bool>,
}

#[derive(Default)]
pub struct Launch {
    pub code: Option<String>,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub ssh_pubkey: Option<String>,
    pub ssh_only: bool,
    /// The settings file could not be used. Nothing should start by itself.
    pub problem: Option<String>,
}

fn filled(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// The command line wins, then the environment, then the file.
pub fn resolve(cli: Options, env: Options, file: Options) -> Launch {
    let code = filled(cli.code).or(filled(env.code)).or(filled(file.code));
    let cli_key = filled(cli.ssh_pubkey);
    let file_key = filled(file.ssh_pubkey);
    // A key handed over this way means a package made for remote support, which
    // must not depend on a virtual NIC. `VARCO_SSH_PUBKEY` predates that and keeps
    // the meaning it always had.
    let default_ssh_only = cli_key.is_some() || file_key.is_some();
    Launch {
        code,
        server: filled(cli.server)
            .or(filled(env.server))
            .or(filled(file.server)),
        port: cli.port.or(env.port).or(file.port),
        ssh_pubkey: cli_key.or(filled(env.ssh_pubkey)).or(file_key),
        ssh_only: cli
            .ssh_only
            .or(env.ssh_only)
            .or(file.ssh_only)
            .unwrap_or(default_ssh_only),
        problem: None,
    }
}

/// `tool.exe` and `tool` both read `tool.toml`. Only `.exe` is removed: released
/// Linux names contain dots that are not extensions, as in `varco-0.2.0-linux-x64`.
pub fn config_path_for(exe: &Path) -> Option<PathBuf> {
    let name = exe.file_name()?.to_str()?;
    let stem = match name.len().checked_sub(4) {
        Some(at) if name.is_char_boundary(at) && name[at..].eq_ignore_ascii_case(".exe") => {
            &name[..at]
        }
        _ => name,
    };
    Some(exe.with_file_name(format!("{stem}.toml")))
}

fn parse_file(text: &str, name: &str) -> Result<Options, String> {
    // Only the message: the full error quotes the line, which may hold the Code.
    toml::from_str(text).map_err(|error| format!("配置文件 {name} 有误：{}", error.message()))
}

fn read_file(path: &Path) -> Result<Options, String> {
    let name = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    match std::fs::read_to_string(path) {
        Ok(text) => parse_file(&text, &name),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Options::default()),
        Err(error) => Err(format!("无法读取配置文件 {name}（{error}）")),
    }
}

/// A broken file is reported instead of being ignored, because ignoring it would
/// start the program in a different mode from the one its author wrote down.
pub fn load(cli: Options, env: Options) -> Launch {
    let path = std::env::current_exe()
        .ok()
        .and_then(|exe| config_path_for(&exe));
    let (file, problem) = match path.map(|path| read_file(&path)) {
        Some(Ok(file)) => (file, None),
        Some(Err(problem)) => (Options::default(), Some(problem)),
        None => (Options::default(), None),
    };
    Launch {
        problem,
        ..resolve(cli, env, file)
    }
}

impl Launch {
    /// The address settings go with the configured Code. A different one pasted
    /// into the window names its own server and is left as it is.
    pub fn credential(&self, code: &str) -> Result<Credential, String> {
        let credential =
            Credential::parse(code).map_err(|_| FailReason::BadCredential.to_string())?;
        let same_code = self
            .code
            .as_deref()
            .is_none_or(|configured| configured.trim() == code.trim());
        if !same_code {
            return Ok(credential);
        }
        credential
            .with_address(self.server.as_deref(), self.port)
            .map_err(|_| "服务端地址或端口无效".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_code(code: &str) -> Options {
        Options {
            code: Some(code.to_owned()),
            ..Options::default()
        }
    }

    fn with_key(key: &str) -> Options {
        Options {
            ssh_pubkey: Some(key.to_owned()),
            ..Options::default()
        }
    }

    fn none() -> Options {
        Options::default()
    }

    #[test]
    fn config_sits_beside_the_executable_under_its_name() {
        for (exe, expected) in [
            ("/a/varco.exe", "/a/varco.toml"),
            ("/a/VARCO.EXE", "/a/VARCO.toml"),
            ("/a/varco", "/a/varco.toml"),
            (
                "/a/varco-0.2.0-windows-x64.exe",
                "/a/varco-0.2.0-windows-x64.toml",
            ),
            ("/a/varco-0.2.0-linux-x64", "/a/varco-0.2.0-linux-x64.toml"),
            ("/a/.exe", "/a/.toml"),
        ] {
            assert_eq!(
                config_path_for(Path::new(exe)).unwrap(),
                Path::new(expected),
                "{exe}"
            );
        }
    }

    #[test]
    fn file_accepts_every_setting() {
        let file = parse_file(
            "code = \"c\"\nserver = \"s\"\nport = 1\nssh_pubkey = \"k\"\nssh_only = false\n",
            "t.toml",
        )
        .ok()
        .unwrap();
        assert_eq!(file.code.as_deref(), Some("c"));
        assert_eq!(file.server.as_deref(), Some("s"));
        assert_eq!(file.port, Some(1));
        assert_eq!(file.ssh_pubkey.as_deref(), Some("k"));
        assert_eq!(file.ssh_only, Some(false));
    }

    #[test]
    fn file_mistakes_are_named_without_quoting_the_secret() {
        for text in [
            "cod = \"varco1.SECRET\"\n",
            "code = \"varco1.SECRET\"\nport = \"x\"\n",
            "code = \"varco1.SECRET\n",
        ] {
            let problem = parse_file(text, "t.toml").err().unwrap();
            assert!(problem.contains("t.toml"), "{problem}");
            assert!(!problem.contains("SECRET"), "{problem}");
        }
    }

    #[test]
    fn a_missing_file_is_fine() {
        let path = std::env::temp_dir().join("varco-no-such-file.toml");
        assert!(read_file(&path).is_ok());
    }

    #[test]
    fn command_line_beats_environment_beats_file() {
        let cli = Options {
            code: Some("cli".into()),
            server: Some("cli".into()),
            port: Some(1),
            ssh_pubkey: Some("cli".into()),
            ssh_only: Some(false),
        };
        let env = Options {
            code: Some("env".into()),
            ssh_pubkey: Some("env".into()),
            ..none()
        };
        let file = Options {
            code: Some("file".into()),
            server: Some("file".into()),
            port: Some(3),
            ssh_pubkey: Some("file".into()),
            ssh_only: Some(true),
        };
        let launch = resolve(cli, env, file);
        assert_eq!(launch.code.as_deref(), Some("cli"));
        assert_eq!(launch.server.as_deref(), Some("cli"));
        assert_eq!(launch.port, Some(1));
        assert_eq!(launch.ssh_pubkey.as_deref(), Some("cli"));
        assert!(!launch.ssh_only);

        let launch = resolve(none(), with_code("env"), with_code("file"));
        assert_eq!(launch.code.as_deref(), Some("env"));
        let launch = resolve(none(), none(), with_code("file"));
        assert_eq!(launch.code.as_deref(), Some("file"));
    }

    #[test]
    fn empty_settings_count_as_absent() {
        let launch = resolve(with_code("  "), none(), with_code("file"));
        assert_eq!(launch.code.as_deref(), Some("file"));
        let launch = resolve(none(), with_key(""), none());
        assert_eq!(launch.ssh_pubkey, None);
    }

    #[test]
    fn a_handed_over_key_means_ssh_only_unless_told_otherwise() {
        assert!(!resolve(none(), none(), none()).ssh_only);
        assert!(!resolve(with_code("c"), none(), none()).ssh_only);
        assert!(resolve(with_key("k"), none(), none()).ssh_only);
        assert!(resolve(none(), none(), with_key("k")).ssh_only);
        let refused = Options {
            ssh_only: Some(false),
            ..with_key("k")
        };
        assert!(!resolve(none(), none(), refused).ssh_only);
    }

    #[test]
    fn the_older_environment_key_keeps_the_virtual_nic() {
        assert!(!resolve(none(), with_key("k"), none()).ssh_only);
    }

    fn sample_code() -> String {
        Credential {
            server: "code.example.com:8443".into(),
            pin: [7; 32],
            secret: [9; 32],
        }
        .encode()
    }

    #[test]
    fn address_settings_apply_to_the_configured_code() {
        let code = sample_code();
        let launch = Launch {
            code: Some(code.clone()),
            server: Some("other.example.com".into()),
            port: Some(9000),
            ..Launch::default()
        };
        let credential = launch.credential(&format!(" {code}\n")).unwrap();
        assert_eq!(credential.server, "other.example.com:9000");
        assert_eq!(credential.pin, [7; 32]);
        assert_eq!(credential.secret, [9; 32]);
    }

    #[test]
    fn address_settings_apply_when_the_code_is_pasted() {
        let launch = Launch {
            port: Some(9000),
            ..Launch::default()
        };
        let credential = launch.credential(&sample_code()).unwrap();
        assert_eq!(credential.server, "code.example.com:9000");
    }

    #[test]
    fn a_different_code_keeps_its_own_address() {
        let launch = Launch {
            code: Some("varco1.another".into()),
            server: Some("other.example.com".into()),
            ..Launch::default()
        };
        let credential = launch.credential(&sample_code()).unwrap();
        assert_eq!(credential.server, "code.example.com:8443");
    }

    #[test]
    fn bad_input_is_reported() {
        assert!(Launch::default().credential("nonsense").is_err());
        let launch = Launch {
            server: Some("has space".into()),
            ..Launch::default()
        };
        assert!(launch.credential(&sample_code()).is_err());
    }
}
