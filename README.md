# varco

[官网](https://lab.vmins.com/varco/) · [下载](../../releases/latest)

凭证接入的 TCP 组网工具。打开程序，粘贴 Code，确认后加入组网。组网内的机器可以互通，除此之外什么也访问不了。

```
客户端 A: 虚拟网卡 <-> TLS/TCP ─┐
客户端 B: 虚拟网卡 <-> TLS/TCP ─┼─ varco server（按目标 IP 转发）
客户端 C: 虚拟网卡 <-> TLS/TCP ─┘
```

服务端没有虚拟网卡，也不向外转发，所以客户端没有通往服务器本机、云内网或公网的路径。全部流量走一个 TCP 端口。

需要远程调试时，[内置 SSH](#内置-ssh-服务器v020-起) 不用对方安装任何东西。对方电脑建不起虚拟网卡也没关系，[仅 SSH 模式](#仅-ssh-模式)依然能让你连上去。

## 下载

[官网](https://lab.vmins.com/varco/)会按你的系统直接下载，也可以在 [Releases](../../releases) 页面选择：

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

程序本身不含任何服务器地址，要连哪台服务器完全由 Code 决定。

程序没有正式代码签名，首次运行可能被系统拦截：

- **Windows SmartScreen**：点“更多信息”，再点“仍要运行”。
- **macOS**：执行 `xattr -dr com.apple.quarantine varco.app`。

无法打开窗口时会自动改用命令行，也可以用 `--cli` 指定。

### 常见错误

| 提示 | 处理 |
|---|---|
| Code 格式不正确 | 检查是否复制完整 |
| Code 无效或已被撤销 | 向管理员要新的 Code |
| 这个 Code 已被使用 | 一次性 Code 只能给一台设备。如果不是你用的，请告诉管理员 |
| 这个 Code 已过期 | 向管理员要新的 Code |
| 已被管理员移出 | 联系管理员 |
| 连不上服务器 | 检查网络，以及防火墙是否允许访问服务端端口 |
| 服务器证书与 Code 不符 | 当前网络在拦截加密连接，换一个网络。Code 不会被发出 |
| 没有管理员权限 | 重新打开程序并同意提权 |
| 创建虚拟网卡失败 | 检查安全软件是否拦截；只需要远程调试时可改用[仅 SSH 模式](#仅-ssh-模式)；否则把完整提示发给管理员 |

### 内置 SSH 服务器（v0.2.0 起）

方便远程调试，对方电脑不用安装或开启任何 SSH 服务。连接后在窗口里粘贴**你的公钥**（`.pub` 文件的内容），打开“SSH 服务器”开关，把窗口显示的命令拿到另一台成员上执行：

```sh
ssh -p 2222 emil@10.77.1.3
```

- **能做什么**：交互 shell、执行命令、`scp` / `sftp`、`ssh -L`（只能转发到对方本机 `127.0.0.1`，适合远程调试器和 VS Code Remote）。
- **谁能连**：只监听组网 IP，只有同一工作区的成员能连到端口，并且只认这一个公钥，没有密码登录。
- **默认关闭**：每次启动都是关的，公钥会记住。关开关、断开组网或关闭窗口，所有 SSH 会话和它们启动的进程都会立刻结束。
- **权限**：Windows 上远程 shell 是**管理员**（程序本身已提权）；macOS 和 Linux 窗口版是当前用户；Linux 命令行版（`sudo`）是 root。
- **防火墙**：Windows 会自动添加一条只针对组网网段的规则，退出时删除。macOS 开了应用防火墙时可能需要手动允许；Linux 的 `ufw` 等请自行放行组网网段的 2222 端口。
- **无界面机器**：设置环境变量 `VARCO_SSH_PUBKEY=<公钥>` 即自动开启。
- **注意**：开启后，持有对应私钥的人能完全控制这台电脑，不用时请关闭。

### 仅 SSH 模式

网卡建不起来（比如系统网络配置被劫持或拦截）时，对方电脑可以不创建网卡，只把内置 SSH 暴露到组网里。在加入页勾选“仅 SSH，不创建网卡”，或在命令行运行：

```sh
VARCO_CREDENTIAL=<Code> VARCO_SSH_PUBKEY=<公钥> varco --ssh-only
```

连接方式不变：另一台成员用普通模式加入后执行窗口显示的 `ssh` 命令。

- **不改系统网络**：不创建网卡、不加路由、不加防火墙规则，也不需要虚拟网卡驱动。
- **只有 SSH**：组网流量由程序自己处理，只接受 TCP 2222，这台电脑本机的其他端口不会暴露；`ssh -L` 仍可转发到它的 `127.0.0.1`。
- **不能主动访问**：这台电脑不能访问其他成员。
- **其他规则相同**：公钥、会话随退出结束等都和上面一样。Windows 版程序仍会请求管理员权限，远程 shell 也仍是管理员。

### 一键拉起

把你的 SSH 公钥编进 Code，**只发这一段 Code**：对方粘贴、点确认，就同时完成入网和开启 SSH，默认用[仅 SSH 模式](#仅-ssh-模式)，不创建网卡。

**生成**，三种方式都不需要联网，密钥不变，已配置的凭证继续有效：

- **窗口**：在加入页点“生成远程协助 Code”，填入 Code 和公钥，点“复制联合 Code”。
- **已有 Code**：`varco code add-ssh-key --code <Code> --ssh-pubkey ~/.ssh/id_ed25519.pub`，不用改服务端配置，也不用重启。
- **新客户**：在管理后台生成 Code 时填上公钥。

公钥可以写文件路径或公钥文本。

**对方看到什么**：粘贴后、点确认前，窗口会用红字提示“这个 Code 会允许持有私钥的人远程控制这台电脑”，并显示公钥指纹。连接后已连接页也会显示指纹，关闭窗口即断开。

**也可以不用粘贴**：把设置放在程序旁边的同名配置文件里（`varco-windows-x64.exe` 对应 `varco-windows-x64.toml`），或者写进一个 `.cmd`，对方双击就能连上：

```toml
code = "varco://…"
# 以下可选
ssh_pubkey = "ssh-ed25519 AAAA… me@host"   # 优先于 Code 里的公钥
server = "vpn.example.com"                 # 代替 Code 里的服务端地址
port = 8443                                # 代替 Code 里的端口
ssh_only = false                           # 默认：有公钥时为 true
```

```bat
@echo off
"%~dp0varco-windows-x64.exe" --code "varco://…"
```

- **优先级**：命令行（`--code`、`--ssh-pubkey`、`--server`、`--port`、`--ssh-only`）> 环境变量（`VARCO_CREDENTIAL`、`VARCO_SSH_PUBKEY`）> 配置文件。
- **改地址是安全的**：`server` 和 `port` 只改变连接目标，证书指纹和密钥仍来自 Code。指向别的服务器只会连接失败，密钥不会发出。
- **写错不会被忽略**：配置文件有错、公钥或 Code 无效时不会连接，并提示原因。
- **公钥不会被记住**：Code、配置文件或命令行带来的公钥不写入用户目录。

使用前请注意：

- **带公钥的 Code 等于远程控制权。** 普通 Code 只能入网，这种 Code 还会把这台电脑的控制权交给私钥持有者，Windows 上是管理员权限。只发给知情并同意的人；收到的人也只应使用可信来源的 Code，并核对指纹。Code 没有签名，拿到 Code 的人可以换掉里面的公钥。
- Code 是明文密钥，配置文件和 `.cmd` 要像 Code 一样保管。
- 命令行参数能被本机其他进程看到，多人共用的电脑上请用配置文件。

macOS 的 `varco.app` 请把配置放在 `varco.app/Contents/MacOS/varco.toml`，或直接用命令行参数。

## 服务端

**1.0 与旧版不兼容**：不再有配置文件，也不迁移旧数据。升级后重新初始化，并重新发 Code。

### 安装（systemd）

记得在防火墙或云安全组放行中继的 TCP 端口（默认 8443）。

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin varco
install -m 755 varco-linux-x64 /usr/local/bin/varco
install -m 644 deploy/varco.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now varco
```

不用写任何配置。启动参数只有两个，因为它们必须在数据库打开之前知道：

| 参数 | 环境变量 | 默认值 |
|---|---|---|
| `--data-dir` | `VARCO_DATA_DIR` | Linux 上是 `/var/lib/varco`，其他系统是用户数据目录下的 `varco-server` |
| `--admin-listen` | `VARCO_ADMIN_LISTEN` | `127.0.0.1:8444` |

### 初始化

1. 把后台端口反向代理出去（见下），或者用 `ssh -L 8444:127.0.0.1:8444 服务器` 临时访问。
2. 用 `root` / `admin` 登录，必须先改密码。密码没有任何限制，可以和原来相同，风险自担。
3. 填写对外地址（写进 Code）和中继监听地址，保存后中继开始监听。
4. 创建第一个工作区。

**默认密码改掉之前，谁先打开页面谁就能接管。** 所以后台默认只监听本机。如果要改成监听外部地址，请先完成初始化。

后台端口是明文 HTTP，对外时请用反向代理加上 HTTPS。例如 nginx：

```nginx
location / {
    proxy_pass http://127.0.0.1:8444;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

挂在子路径下也可以，路径末尾要带 `/`。中继端口不要经过这层代理：它有自己的 TLS，拉黑 IP 也依赖真实的来源地址。

### 工作区和权限

一个工作区就是一张组网，给一个团队用。不同工作区的成员互不可达、互相看不到，网段可以重叠。同一个程序可以直接发给不同团队，连到哪个工作区完全由 Code 决定。

| 身份 | 能做什么 |
|---|---|
| 超管（`root`） | 管理所有工作区；创建和删除工作区、改网段；全局黑名单和审计；服务设置；所有账号 |
| owner | 工作区内的所有操作，加上增删管理员、改角色、重置只属于本工作区的账号的密码 |
| 管理员 | 看成员和历史、踢人、拉黑、生成和撤销 Code、管理 Token |

访问没有权限的工作区一律返回“不存在”。新账号首次登录必须改密码，同样没有限制。连续输错 5 次密码，这个账号要等 1 分钟才能再试，不影响其他账号。

### Code

| 类型 | 规则 |
|---|---|
| 一次性 | 只能使用 1 次，本身不会过期 |
| 限时 | 到期前不限次数，到期后不再接受新的使用 |
| 限时限次 | 两者都有，比如 7 天内最多 3 次 |
| 永久 | 没有限制，适合无人值守的机器 |

- **期限只限制开始使用。** 程序一直开着就不受影响，断线和服务端重启后都能自动重连。
- **“次”按运行计算。** 关闭窗口或重启程序后再用，算新的一次。所以有限制的 Code 不适合无人值守的机器。
- **网卡建好才算用掉。** 没有管理员权限、创建网卡失败都不会浪费次数。
- **完整的 Code 只在生成时显示一次**，服务端只存哈希。
- 可以改备注、改期限（不影响已连接的设备）。永久 Code 不能再加期限，请撤销后重新生成。

### 管理操作

都立即生效，不用重启：

| 操作 | 效果 |
|---|---|
| 踢出 | 断开并结束这次运行，不再自动重连。对方重开程序后，只要 Code 还有效就能回来。记录保留 7 天，可以解除 |
| 拉黑设备 | 重开程序或换 Code 都进不来 |
| 拉黑 IP 或网段 | 断开匹配的连接并拒绝新连接，同一出口后的所有人都会受影响。可以设到期时间 |
| 撤销 Code | 不再接受新连接，用它进来的设备也会被踢出 |
| 改网段 | 所有成员断开，重连后拿到新地址 |
| 删除工作区 | 所有成员断开并停止重连，Code、记录和只属于它的账号一并删除 |

工作区的黑名单只在自己的工作区生效。超管的全局黑名单对所有工作区生效，其中的 IP 在 TLS 之前就被丢弃，对方只看到连不上。

**设备 ID 的限制：** 它来自操作系统的机器 ID（Linux 的 `/etc/machine-id`、macOS 的 `IOPlatformUUID`、Windows 的 `MachineGuid`），经哈希后上报。它由客户端自己上报，改过的客户端可以伪造；克隆的虚拟机或系统镜像可能共用同一个 ID，拉黑时会一起受影响；读不到时显示“未知设备”，不能按设备拉黑。要真正拦住一个人，还要撤销 Code。

### 自动化

在后台创建 Token，用 `Authorization: Bearer <Token>` 调用和页面相同的 `/api/...` 接口。Token 只显示一次。工作区 Token 的权限等同这个工作区的普通管理员，超管 Token 等同超管。

| 地址 | 权限 | 内容 |
|---|---|---|
| `/healthz` | 无需登录 | 中继是否在监听 |
| `/metrics` | 超管 | Prometheus 格式：各工作区在线数、地址容量、收发字节，以及中继状态 |

### 运维

```sh
# 忘记 root 密码：恢复成 admin，并退出它的所有登录
runuser -u varco -- varco server --data-dir /var/lib/varco reset-root-password

# 服务日志
journalctl -u varco -f
```

- **备份数据目录**：`varco.db` 存工作区、账号、Code 和黑名单；`varco-server.key` 决定所有 Code 里的证书指纹，丢失后所有 Code 都要重发。文件损坏时服务端拒绝启动，不会当作空数据继续运行。
- **修改对外地址**：只影响新 Code，已发出的 Code 仍指向旧地址。
- **修改中继监听地址**：已连接的成员不受影响。新地址绑定失败时保留旧地址。
- **历史保留**：连接历史和审计默认保留 30 天，可在服务设置里修改。审计的来源地址来自代理上报，仅供参考。

## 需要知道的

- **成员之间完全互通**：同一工作区的成员能访问彼此在组网接口上监听的所有端口，也能看到彼此的主机名和 IP。
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
