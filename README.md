# fanout

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

把 VPN Gate 的公共节点变成本地 SOCKS5 端口：一个端口一个出口 IP。
再给每个出口挂一个节点链接，客户端连哪个端口就从哪个国家出去。

fanout 统一由 sing-box 管理节点入站和 VPN Gate 出口，建站、改站、发链接都在同一个界面里完成。

![主界面](https://images.joeyblog.net/2026/7/27/fanout-dashboard.png)

四条隧道跑在一台机器上，四个端口对应四个国家的出口，母机自己的 IP 不受影响：

![出口验证](https://images.joeyblog.net/2026/7/26/fanout-6-exit-ip.png)

## 原理

每个出口启动一个独立的 sing-box 进程。进程内使用 `system: false` 的 OpenVPN
endpoint 和 gVisor 用户态网络栈，不创建系统 TUN 接口，也不改宿主路由或防火墙。
公网 SOCKS5 仍由 fanout 监听和鉴权，内部流量再交给该出口的 loopback SOCKS5。
因此换节点或掉线重连只影响这一条出口。

```
客户端 ──> fanout SOCKS5 :随机端口 ──> sing-box SOCKS5 (loopback) ──> OpenVPN endpoint ──> VPN Gate 节点
```

## 安装

安装服务需要 root，运行时不依赖 netns、iptables 或 `/dev/net/tun`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/fanout/main/install.sh)
```

会自动下载对应架构的预编译二进制。也可以 clone 仓库后在源码目录运行同一个脚本，
那样会从源码编译（需要 Go 1.24+）。

安装脚本只会补齐 `curl` 和 `tar`，再下载 fanout 与最新版 sing-box 到
`/var/lib/fanout/bin/`。运行时要求 sing-box `>=1.14.0`（支持后续版本），且必须带
`with_openvpn,with_gvisor` 两个构建标签。也可以通过 `SINGBOX_VERSION=...` 指定版本。

OpenVPN endpoint 在 sing-box 1.14 中仍是预发布能力。生产使用前应先在目标地区
实测 VPN Gate 节点兼容性；如果需要可重复部署，建议通过 `SINGBOX_VERSION=...` 固定版本。

服务用 systemd 或 OpenRC 都能装，装完自动开机自启。

自建节点默认监听 IPv4 wildcard `0.0.0.0`。需要让 Hysteria2/TUIC 接收 IPv6 客户端时，
启动参数改为：

```bash
./fanout -inbound-listen :: -web 8899 -dir /var/lib/fanout
```

Linux 默认会把 `::` 作为 IPv6 wildcard，并通常同时接受 IPv4-mapped 连接；如果系统开启了
`net.ipv6.bindv6only=1`，它只会监听 IPv6，此时请改回 `0.0.0.0` 或调整系统 socket 策略。

sing-box 可以选择 `ipv4_only` / `ipv6_only` DNS 解析，但不内置完整 NAT64/DNS64 网关。
fanout 会让双栈域名优先走绑定的 IPv4 OpenVPN；IPv6-only 目标则绕过 VPN、直接走 VPS 的
IPv6 出口。若 VPS 本身没有 IPv6，纯 IPv6 目标仍需在服务器或上游网络提供 Jool、Tayga
或运营商 NAT64。

**Alpine** 默认不带 bash，先装一下：

```bash
apk add bash
bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/fanout/main/install.sh)
```

装完敲 `f` 打开管理菜单：

![管理菜单](https://images.joeyblog.net/2026/7/26/fanout-7-menu.png)

装完会打印管理界面地址、访问路径和口令：

```
管理界面  http://<你的IP>:8899/gwPuWHvaNr/
访问口令  f81120ac328d11c11b
```

路径和口令都是随机生成的，分别存在 `/var/lib/fanout/basepath` 和
`/var/lib/fanout/password`。路径不对一律返回 404，扫端口的看不到这里跑着什么。

## 使用

界面以**出口**为单位：一行就是一条隧道加上挂在它上面的节点链接。

点「新建出口」，选地区和数量，再选一个已有节点作模板，提交后 fanout 会并行
拉起隧道、为每个出口复制一份节点链接并绑好，进度按目标逐条回报。原来要手点
五步跨两栏的事，现在一次点击十几秒完成。

![新建出口](https://images.joeyblog.net/2026/7/27/fanout-wizard.png)

每行右侧两个按钮：换一个节点（出口 IP 变、端口不变，已分发的客户端配置不用改），
或者停掉这个出口。

点节点名进详情，可以改端口、备注、启停，管理客户端，以及改绑到别的出口：

![节点详情](https://images.joeyblog.net/2026/7/27/fanout-detail.png)

一个入站可以挂多套客户端凭据，分发给不同的人；每套都能单独重置，
重置后旧链接立即失效。

「导出链接」一次性拿到所有节点链接：

![导出链接](https://images.joeyblog.net/2026/7/27/fanout-export.png)

### 节点链接从哪来

fanout 自己运行 sing-box，界面提供「新建节点」按钮，可以选协议
（VLESS / VMess / Trojan / Hysteria2 / TUIC）、传输（TCP / WebSocket / gRPC /
HTTPUpgrade / UDP-QUIC）和安全层（无 / TLS / REALITY）。Hysteria2 与 TUIC 使用
UDP/QUIC 且强制 TLS；VLESS / VMess / Trojan 仍使用 TCP 类传输。XHTTP 是 Xray 专有传输，不再支持；旧的 XHTTP 入站升级后会
被禁用，需用其他传输重新创建。

![新建节点](https://images.joeyblog.net/2026/7/27/fanout-newnode.png)

REALITY 的密钥对和 shortId 自动生成；TLS 不填证书就生成自签的，分享链接会带上
证书指纹让客户端固定信任。也可以填自己的证书路径。

## 运维

装完后敲 `f` 打开管理菜单：启停、看日志、查隧道、改端口/口令/访问路径、更新、卸载。

```
  状态      运行中
  版本      fanout v0.1.1
  开机自启  enabled

  管理地址  http://1.2.3.4:8899/gwPuWHvaNr/
  访问口令  f81120ac328d11c11b

   1) 启动          2) 停止
   3) 重启          4) 查看日志
   5) 隧道列表      6) 连接信息
   7) 改端口        8) 改口令
   9) 改访问路径   10) 开机自启开关
  11) 更新         12) 卸载
```

也可以直接带参数用：

```bash
f info       # 连接信息
f list       # 隧道列表
f restart    # 重启
f log        # 跟踪日志
f update     # 更新到最新版
f uninstall  # 卸载
```

隧道状态存在 `/var/lib/fanout/state.json`，重启后自动恢复，端口保持不变。

健康检查每 10 秒经当前出口查询一次 IP，比对是否仍为建立时的出口。连续两次失败或
不符就自动换节点重连，槽位和端口不变，原先指向它的节点链接会自动改绑过去。

## 已知限制

- Hysteria2/TUIC 入站可以转发 TCP 和 UDP；出口通过每条隧道的 sing-box 内部 SOCKS
  访问 OpenVPN。单独提供给用户的 fanout SOCKS5 端口仍只支持 TCP CONNECT。
- VPN Gate 是志愿者节点，有相当比例已下线或满员（`AUTH_FAILED`）。
  启动时连不上会自动顺着同地区候选往下试，最多 6 个。
- 管理界面只有随机路径 + 口令登录，没有 HTTPS。放公网建议前面套一层反代。

## 许可

[MIT](LICENSE)。

sing-box 是单独下载和运行的 GPLv3 程序，许可见其上游项目。

节点来自 [VPN Gate](https://www.vpngate.net/)（筑波大学的学术实验项目），
本工具只是调用其公开的节点列表，并用 sing-box 的 OpenVPN client endpoint 连接，
不修改也不代理其服务。
使用时请遵守 VPN Gate 的条款和你所在地的法律。

## 交流

- 交流群：<https://t.me/+ft-zI76oovgwNmRh>
- 视频教程：<https://youtube.com/@joeyblog>
- 博客：<https://joeyblog.net>

用着有问题、或者想要什么功能，去群里说或提 issue。
