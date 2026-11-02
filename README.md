# varco

[官网](https://lab.vmins.com/varco/) · [下载](../../releases/latest)

凭证接入的 TCP 组网工具。打开程序，粘贴 Code，确认后加入组网。组网内的机器可以互通，除此之外什么也访问不了。

```
客户端 A: 虚拟网卡 <-> TLS/TCP ─┐
客户端 B: 虚拟网卡 <-> TLS/TCP ─┼─ varco server（按目标 IP 转发）
客户端 C: 虚拟网卡 <-> TLS/TCP ─┘
```

服务端没有虚拟网卡，也不向外转发，所以客户端没有通往服务器本机、云内网或公网的路径。全部流量走一个 TCP 端口。

## 下载

在 [Releases](../../releases) 页面下载：

| 平台 | 文件 | 用途 |
|---|---|---|
| Windows | `varco-windows-x64.exe`、`varco-windows-arm64.exe` | 窗口客户端 |
| macOS | `varco-macos-arm64.zip`、`varco-macos-x64.zip` | 窗口客户端 |
| Linux 桌面 | `varco-linux-gui-x64`、`varco-linux-gui-arm64` | 窗口客户端，需要 glibc 2.36 以上和 fontconfig |
| Linux 服务器 | `varco-linux-x64`、`varco-linux-arm64` | 服务端和无界面客户端，静态链接 |

## 客户端

打开程序，粘贴管理员发来的 Code，点确认。连接后窗口会显示本机 IP、网段、延迟、流量和在线成员。断线时自动重连，IP 不变；关闭窗口即断开。

| 平台 | 打开方式 |
|---|---|
| Windows | 双击 exe，同意 UAC |
| macOS | 解压后打开 `varco.app`，点确认后输入系统密码 |
| Linux 桌面 | `chmod +x` 后运行，点确认后通过 pkexec 授权 |
| Linux 无界面 | `sudo varco --cli`，或 `sudo VARCO_CREDENTIAL=<Code> varco` 用于无人值守 |

程序没有正式代码签名，首次运行可能被系统拦截：

- **Windows SmartScreen**：点“更多信息”，再点“仍要运行”。
- **macOS**：执行 `xattr -dr com.apple.quarantine varco.app`。

无法打开窗口时会自动改用命令行，也可以用 `--cli` 指定。

### 常见错误

| 提示 | 处理 |
|---|---|
| Code 格式不正确 | 检查是否复制完整 |
| Code 无效或已被撤销 | 向管理员要新的 Code |
| 连不上服务器 | 检查网络，以及防火墙是否允许访问服务端端口 |
| 服务器证书与 Code 不符 | 当前网络在拦截加密连接，换一个网络。Code 不会被发出 |
| 没有管理员权限 | 重新打开程序并同意提权 |
| 创建虚拟网卡失败 | 检查安全软件是否拦截；把完整提示发给管理员 |

### 内置 SSH 服务器（v0.2.0 起）

方便远程调试，对方电脑不用安装或开启任何 SSH 服务。连接后在窗口里粘贴**你的公钥**（`.pub` 文件的内容），打开“SSH 服务器”开关，把窗口显示的命令拿到另一台成员上执行：

```sh
ssh -p 2222 emil@10.77.1.3
```

- **能做什么**：交互 shell、执行命令、`scp` / `sftp`、`ssh -L`（只能转发到对方本机 `127.0.0.1`，适合远程调试器和 VS Code Remote）。
- **谁能连**：只监听组网 IP，只有同一 network 的成员能连到端口，并且只认这一个公钥，没有密码登录。
- **默认关闭**：每次启动都是关的，公钥会记住。关开关、断开组网或关闭窗口，所有 SSH 会话和它们启动的进程都会立刻结束。
- **权限**：Windows 上远程 shell 是**管理员**（程序本身已提权）；macOS 和 Linux 窗口版是当前用户；Linux 命令行版（`sudo`）是 root。
- **防火墙**：Windows 会自动添加一条只针对组网网段的规则，退出时删除。macOS 开了应用防火墙时可能需要手动允许；Linux 的 `ufw` 等请自行放行组网网段的 2222 端口。
- **无界面机器**：设置环境变量 `VARCO_SSH_PUBKEY=<公钥>` 即自动开启。
- **注意**：开启后，持有对应私钥的人能完全控制这台电脑，不用时请关闭。

## 服务端

### 配置

端口、服务端地址（IP 或域名）、网段和凭证都在配置文件里，二进制不含任何部署信息。以 [`config.example.toml`](config.example.toml) 为模板。每个客户用一个单独的 network，不同 network 之间不通。

真实配置只放在服务器上：`config.toml`、密钥和 Code 文件都已被 `.gitignore` 排除，不要提交。

### 部署（systemd）

记得在防火墙或云安全组放行 `listen` 的 TCP 端口。

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin varco
install -d -o varco -g varco -m 700 /etc/varco
install -m 755 varco-linux-x64 /usr/local/bin/varco
install -m 644 deploy/varco.service /etc/systemd/system/

# 按模板写好配置
install -o varco -g varco -m 600 config.example.toml /etc/varco/config.toml
vi /etc/varco/config.toml

systemctl daemon-reload
systemctl enable --now varco
```

### 日常操作

```sh
# 生成凭证：把输出的密钥写进对应 network 的 credentials，把 Code 发给对方
runuser -u varco -- varco server -c /etc/varco/config.toml gen-credential --network customer-a
systemctl restart varco

# 查看上线记录（主机名 -> IP）
journalctl -u varco -f
```

- **撤销凭证**：从 `credentials` 删除后重启服务。该凭证的客户端重连时会被拒绝。
- **增删凭证或网络**：要重启服务。客户端会自动重连，IP 不变。
- **修改 `public_addr`**：要重新生成并分发 Code，已发出的 Code 仍指向旧地址。
- **备份 `varco-server.key`**：它决定所有已发出 Code 里的证书指纹，丢失后所有 Code 都要重发。

## 需要知道的

- **成员之间完全互通**：同一 network 的成员能访问彼此在组网接口上监听的所有端口，也能看到彼此的主机名和 IP。
- **开启 SSH 等于交出这台电脑**：组网隔离的是网络，不限制你在对方机器上的操作。默认关闭，只给信任的公钥。
- **服务端能看到明文**：TLS 在服务端终止，组网内的流量在服务端进程里是明文的。需要保密的内容请在应用层加密，比如 SSH。
- **只支持 IPv4**，全部流量经服务端中转。

## 开发

```sh
cargo test                # 单元测试和真实 TLS 上的集成测试，不需要 root
tests/e2e/run.sh          # Docker 内真实 TUN 的端到端测试，约 6 分钟
cargo run --features gui  # 带窗口运行（Linux 需要 libfontconfig1-dev）
scripts/package.sh        # 在 macOS 上本地构建发布产物到 dist/
```

## CI / 发布

| 工作流 | 触发 | 内容 |
|---|---|---|
| CI | 推送到 main、Pull Request | fmt、clippy；Linux / macOS / Windows 测试；端到端测试 |
| Release | 推送 `v*` 标签 | 构建全部平台，附校验和发布到 Releases |
| Release（手动运行） | Actions 页面 | 只构建产物，不发布 |
| Website | `site/` 有改动并推送到 main | 部署官网到 GitHub Pages |

发布新版本：修改 `Cargo.toml` 的 `version`，提交后执行：

```sh
git tag v0.2.0 && git push origin v0.2.0
```

## 许可证

本项目代码采用 [MIT](LICENSE) 许可证。下列第三方组件各自遵循自己的许可证。

## 第三方组件

- [Slint](https://slint.dev)：Royalty-free License 2.0，程序内“关于”页显示其声明
- Noto Sans SC 子集：SIL OFL 1.1，见 `assets/fonts/OFL-LICENSE.txt`
- 官网字体 Instrument Serif、JetBrains Mono：SIL OFL 1.1，见 `site/fonts/`
- [russh](https://github.com/Eugeny/russh)、russh-sftp：Apache-2.0；[portable-pty](https://github.com/wezterm/wezterm)：MIT
- [Wintun](https://www.wintun.net)：内嵌未修改的官方签名 DLL，许可证见 `vendor/wintun/LICENSE.txt`
