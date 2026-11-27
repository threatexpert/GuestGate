<h1 align="center">GuestGate</h1>

<p align="center">
  <strong>VMware 虚拟机透明代理网关</strong><br>
  整机流量经 SOCKS5 转发 · 每台虚拟机可单独配置 · 严格隔离模式防止直连泄露
</p>

<p align="center">
  欢迎扫码加入微信群讨论 <a href="./wechat-qr.svg"><img src="./wechat-qr.svg" width="57" height="57" align="absmiddle" alt="微信群二维码，点击放大"></a>
</p>

---

GuestGate 运行在 Windows 宿主机上。选一台正在运行的 VMware 虚拟机，填入 SOCKS5 地址，就能让虚拟机里的应用通过代理上网，无需逐个设置。你也可以给多台虚拟机指定不同的代理，分别启停。

严格隔离模式默认开启。GuestGate 会把虚拟机接入专用网络，阻断对宿主机端口的访问。代理断开或 GuestGate 停止后，虚拟机仍留在这个网络，不会自动切回 NAT 或桥接上网。

![GuestGate 主界面](./UI.png)

## 工作原理

**架构级防漏原理（零直出保障）**

1. **先切断外网：** 将虚拟机网卡设为仅主机模式（Host-Only）或隔离模式，从底层剥夺其直连公网的能力。
2. **单点搭桥：** GuestGate 直接监听该虚拟机网卡的底层数据包，并实现将其透明代理转发至上游代理。

**可靠性闭环：** GuestGate 是虚拟机通往外部的唯一桥梁。无论代理服务停止、程序意外退出还是上游节点故障，桥梁断开即刻彻底断网。

## 快速使用

准备一台装有 VMware Workstation 和 WebView2 的 Windows x64 宿主机。虚拟机只配置一个网络适配器，并启用 DHCP 自动获取 IP。

1. 启动虚拟机，在宿主机上以管理员身份运行 `GuestGate.exe`。
2. 在左侧选中虚拟机，填写上游 SOCKS5 地址，例如 `127.0.0.1:1080`。需要认证时可填 `socks5://用户名:密码@主机:端口`。
3. 点击 **启用隔离网络并代理**，核对出口 IP 和归属地后，点击 **确认并启用代理**。会话显示 **已就绪 · 代理运行中** 即可使用。

点击 **停止代理** 可单独停止这台虚拟机的会话。要查看连接的目标地址、DNS 查询或失败原因，展开窗口底部的 **活动日志**。

## 从源码构建

使用 `go.mod` 指定的 Go 版本，并将 GNU windres 加入 PATH。在项目目录运行以下 PowerShell 命令即可测试并生成 `GuestGate.exe`。

```powershell
go test ./...
.\scripts\build-windows.ps1
```

## 许可证

[MIT License](LICENSE)
