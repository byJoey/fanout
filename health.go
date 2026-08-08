package main

import (
	"log"
	"time"
)

const (
	healthInterval = 10 * time.Second
	healthFailures = 2 // 连续失败几次才判定掉线，避免网络抖动误杀
	healthTimeout  = 6 * time.Second
)

// WatchHealth 周期检查每条隧道是否还能出网，掉线的自动换节点重连。
// VPN Gate 是志愿者节点，运行中掉线很常见。
func (m *Manager) WatchHealth() {
	fails := map[int]int{}

	for range time.Tick(healthInterval) {
		for _, t := range m.Tunnels() {
			if t.Status != "up" {
				continue
			}
			if m.tunnelHealthy(t) {
				fails[t.Slot] = 0
				continue
			}

			fails[t.Slot]++
			if fails[t.Slot] < healthFailures {
				log.Printf("隧道 %d (%s) 探测失败 %d 次", t.Slot, t.Node.HostName, fails[t.Slot])
				continue
			}

			log.Printf("隧道 %d (%s) 已掉线，正在换节点重连", t.Slot, t.Node.HostName)
			fails[t.Slot] = 0
			m.reconnect(t, t.Node.HostName)
		}
	}
}

// tunnelHealthy 判断隧道是否还真的走在 VPN 上。
//
// 比对出口 IP 可以同时发现 endpoint 已断线和服务端出口发生变化。
func (m *Manager) tunnelHealthy(t *Tunnel) bool {
	got, err := t.probeExitIP(healthTimeout)
	if err != nil {
		return false
	}
	return got == t.ExitIP
}

// reconnect 就地把一条隧道换到别的节点上，保持槽位与端口不变，
// 这样已经分发出去的客户端配置仍然可用。
//
// oldHost 必须是本次重连前那条隧道真正绑着的节点名。调用方若已经
// 改过 t.Node（比如手动换节点），就要把改之前的名字传进来，
// 否则 rebind 找不到旧绑定，入站会掉成孤儿。
func (m *Manager) reconnect(t *Tunnel, oldHost string) {
	t.Status = "starting"
	t.Err = "正在换节点重连"
	t.ExitIP = ""

	t.stopEngine()

	go func() {
		// 通知延后到 rebind/resync 之后：那两步会把入站改绑到新节点，
		// 提前重建配置会因为入站还指着旧节点名而丢掉路由规则
		m.bringUpPersist(t, false, true)
		if t.Status != "up" {
			return
		}
		// 出站 tag 跟着节点名走，换了节点就要把原来指向它的入站重新绑过去，
		// 否则面板里的路由会指向一个已经不存在的出站。
		if t.Node.HostName != oldHost {
			if err := m.rebind(oldHost, t); err != nil {
				log.Printf("重连后同步入站绑定失败: %v", err)
			}
			return
		}
		// 节点名没变也要重写一次出站：出口 IP 可能变了，
		// 而且上一轮换节点时留下的绑定需要重新指回来。
		if err := m.resync(t); err != nil {
			log.Printf("重连后刷新 sing-box 出站失败: %v", err)
		}
	}()
}
