use serde::{Deserialize, Serialize};
use std::fmt;

/// Why joining failed, worded for the person at the keyboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailReason {
    BadCredential,
    ServerUnreachable(String),
    PinMismatch,
    CredentialRejected,
    CodeUsed,
    CodeExpired,
    Removed,
    NetworkFull,
    VersionMismatch,
    NoPrivilege,
    DeviceFailed(String),
    Protocol(String),
}

impl FailReason {
    /// Retrying cannot help these, even when a session was established before.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::BadCredential
                | Self::CredentialRejected
                | Self::CodeUsed
                | Self::CodeExpired
                | Self::Removed
                | Self::VersionMismatch
                | Self::NoPrivilege
                | Self::DeviceFailed(_)
        )
    }
}

impl fmt::Display for FailReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadCredential => write!(f, "Code 格式不正确，请检查是否复制完整"),
            Self::ServerUnreachable(detail) => {
                write!(f, "连不上服务器，请检查网络或防火墙（{detail}）")
            }
            Self::PinMismatch => write!(
                f,
                "服务器证书与 Code 不符，当前网络可能在拦截加密连接，已中止，Code 未发送"
            ),
            Self::CredentialRejected => write!(f, "Code 无效或已被撤销"),
            Self::CodeUsed => write!(f, "这个 Code 已被使用，如果不是你用的，请告诉管理员"),
            Self::CodeExpired => write!(f, "这个 Code 已过期，请向管理员要新的"),
            Self::Removed => write!(f, "已被管理员移出"),
            Self::NetworkFull => write!(f, "组网地址已用完，请联系管理员"),
            Self::VersionMismatch => write!(f, "程序版本与服务器不兼容，请更新"),
            Self::NoPrivilege => write!(f, "没有管理员权限，无法创建虚拟网卡"),
            Self::DeviceFailed(detail) => write!(f, "创建虚拟网卡失败（{detail}）"),
            Self::Protocol(detail) => write!(f, "与服务器通信异常（{detail}）"),
        }
    }
}
