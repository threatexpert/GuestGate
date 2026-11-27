# GuestGate

Windows 上的 VMware Workstation Host-only 虚拟机 SOCKS5 网关。一个窗口可同时管理多台运行中的虚拟机。Go 后端和 Wails v2 WebView2 界面沿用 gonc-gui 的分层方式，网络核心复用其固定版本的 threatexpert/tun2socks。

## 使用

1. 在装有 VMware Workstation 和 WebView2 的 Windows x64 宿主机启动 GuestGate.exe，允许管理员权限。
2. 在“运行中的虚拟机”区域点击图标，在下方填写上游 SOCKS5 和 DNS（默认 8.8.8.8）。上游支持 `host:port` 或 `socks5://用户名:密码@host:port`，特殊字符使用 URL 编码。配置自动保存到当前 Windows 用户的 `%APPDATA%\GuestGate\profiles`，按完整 VMX 路径区分。上游、DNS 和填写的 VMware REST 密码使用该用户的 Windows DPAPI 加密。旧版保存的 DNS 在首次读取该虚拟机时自动迁移。
3. 如果网卡连接 NAT、桥接或已删除的网络，点击“切换到仅主机并启用代理”会将运行中的网卡热切换到 VMnet1。已经连接可用 Host-only 的网卡会复用原网络。每台虚拟机的会话卡保留全部五步：检查虚拟机、准备仅主机网络、启动网关、配置 DHCP、确认虚拟机接入。观察到本次 DHCP 租约或代理流量后，卡片显示“已启用”。运行时会显示最近一次 SOCKS5 TCP 连接结果。等待超过 45 秒仍未看到租约或代理流量时，卡片会提示在 guest 内禁用再启用网卡。
4. 在会话卡点击“停止代理”，GG 会停止该虚拟机的转发并撤掉对应的 DHCP 配置。已经切换的网卡会保留在仅主机模式。其他会话继续运行，退出窗口会停止所有会话。

热切换时，Workstation 自带的 vmrest 仅侦听本地 Unix socket。默认安装下，应用临时生成 VMware REST 账户凭据并在切换后删除。已经配置 VMware REST 账户的主机需要在 GuestGate 内输入该账户的密码。

GG 从 Windows 注册表和 VMware 授权服务识别 Workstation 的实际安装位置，并检查系统的 Program Files 目录。当前支持单虚拟网卡、IPv4 Host-only 网段和使用 DHCP 的 guest。网段须隔离，宿主机在该 VMnet 上的 IP 转发须关闭。应用读取实际子网和掩码，优先尝试网络地址加 2，自动跳过 DHCP 地址池、固定保留、宿主机地址和 ARP 探测到的占用地址。已有其他子网网关或找不到可用地址时会提示原因。VMware 的 DHCP 服务在写入或删除选中 MAC 的配置时会短暂重启。其他 Host-only 或 NAT 虚拟机已有租约继续有效，恰好在此期间申请或续租的客户机可能需要重试。VMware NAT 服务继续运行。

## 出口与断网行为

默认使用 Workstation 自带的 vmnetuserif 驱动收发以太网帧，已在 Workstation 17.0.2 build 21581411 上验证。驱动打开、绑定或启动收发检查失败时，才加载已安装的 [Npcap](https://npcap.com/) 作为备用。状态栏显示实际后端。若两个后端均不可用，启用失败。运行期间收发出错会停止网关。

同一 VMnet 的活动虚拟机共享自动选定的网关地址、网关 MAC 和一个驱动端口。GuestGate 按源 MAC 将每个 guest 的以太网帧交给其独立的用户态协议栈和 SOCKS5。用户态 IP 栈代收 IPv4 TCP 和 UDP。TCP 使用定制版的延迟握手。网关读完并验证对应 SOCKS5 CONNECT 的成功应答后才发送 SYN-ACK。代理拒绝会向 guest 返回 RST。普通 UDP 使用代理提供的 UDP ASSOCIATE 中继。每台虚拟机的 UDP DNS 查询共用一个 SOCKS5 UDP 中继。控制连接断开后，GuestGate 自动重新协商。只有上游对 UDP ASSOCIATE 明确回复命令不支持（0x07），本次代理会话才会将 UDP DNS 查询通过同一 SOCKS5 的 CONNECT 转成 TCP DNS。认证失败、网络故障和查询超时均不会触发 TCP 回退。DHCP 下发的 DNS 是 guest 的默认解析器。应用显式查询其他 IPv4 DNS 时，两条转发路径都保留实际目的地址。IPv6、ICMP 和其他协议没有外网转发路径。Host-only 网段内的 DHCP、ARP 和 guest 到宿主机同网段的访问仍属本地通信。

GuestGate 不创建系统 TUN、NAT、默认路由或 Windows 转发规则。代理拒绝请求或不可达时，连接失败。主界面退出或崩溃时，匿名管道关闭，工作进程停止收发并清理活动虚拟机的 DHCP 条目。工作进程被强杀后，残留的 DHCP 网关指向已经停止响应的虚拟 MAC，下次启用时会替换残留块。存在第二张虚拟网卡时应用拒绝启用。同网段其他路由器、手工指定的其他出口超出隔离模型。

## 工程结构

| 位置 | 职责 |
| --- | --- |
| `main.go` | 桌面程序与工作进程入口 |
| `frontend/` | 嵌入程序的界面、样式、脚本和图标 |
| `internal/desktop/` | Wails 界面接口、窗口定位和工作进程通信 |
| `internal/gateway/` | 虚拟机发现与热切换、DHCP、网关转发和会话管理 |
| `internal/vmnet/` | VMware 驱动和 Npcap 以太网收发 |
| `internal/dnsrelay/` | SOCKS5 DNS 中继和 TCP 回退 |
| `internal/workstation/` | 定位本机 Workstation 工具 |
| `internal/profiles/` | 每台虚拟机的配置存储和 Windows DPAPI 加密 |
| `assets/windows/` | Windows 图标与 DPI 清单的资源编译配置 |

## 构建和验证

使用 go.mod 指定的 Go 版本，在项目目录运行：

```powershell
go test ./...
go build -tags production -ldflags '-H windowsgui' -o GuestGate.exe .
```

仓库已包含供 Windows x64 构建使用的 `guestgate_windows_amd64.syso`。修改图标或清单后，在项目根目录使用 GNU windres 重新生成资源：

```powershell
windres --target=pe-x86-64 --preprocessor=cat -i assets/windows/guestgate.rc -o guestgate_windows_amd64.syso -O coff
```

测试网络行为时，先在未启用状态确认 guest 无默认出口。选择代理后，从 guest 请求一个外部 HTTPS 地址，再停止 SOCKS5 对同一地址建立新连接。最后在代理可用的情况下关闭 GuestGate，确认 guest 再次断网。宿主机始终使用自己的路由表。
