package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// persistedTunnel 是隧道在磁盘上的形态。
// 只存重建所需的信息，运行态（进程、监听）重启后重新建立。
type persistedTunnel struct {
	Slot        int    `json:"slot"`
	Port        int    `json:"port"`
	HostName    string `json:"hostname"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Config      string `json:"config"`
	// SOCKS5 凭据要存盘：用户已经把它分发给客户端了，重启后变掉等于全断
	SocksUser string `json:"socks_user,omitempty"`
	SocksPass string `json:"socks_pass,omitempty"`
}

type persistedState struct {
	Tunnels []persistedTunnel `json:"tunnels"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// saveState 把当前隧道写入磁盘，供重启后恢复。
func (m *Manager) saveState() error {
	var st persistedState
	for _, t := range m.Tunnels() {
		// 只跳过用户主动停掉的。starting/failed 的隧道也要存：
		// 它们正在重连或等着重试，漏存会让重启后凭空少几个出口。
		if t.Status == "stopped" {
			continue
		}
		st.Tunnels = append(st.Tunnels, persistedTunnel{
			Slot:        t.Slot,
			Port:        t.Port,
			HostName:    t.Node.HostName,
			CountryCode: t.Node.CountryCode,
			Country:     t.Node.Country,
			Config:      t.Node.Config,
			SocksUser:   t.Cred.User,
			SocksPass:   t.Cred.Pass,
		})
	}

	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(m.workDir) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(m.workDir))
}

// restoreState 读回上次的隧道并逐条拉起。
// 节点配置一并存了盘，所以即使 VPN Gate 列表里该节点已消失也能重建。
func (m *Manager) restoreState() (int, error) {
	blob, err := os.ReadFile(statePath(m.workDir))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	var st persistedState
	if err := json.Unmarshal(blob, &st); err != nil {
		return 0, fmt.Errorf("解析状态文件失败: %w", err)
	}

	// 从当前节点列表补回地区、延迟等元数据；节点已下线时退回存盘的最小信息
	known := map[string]Node{}
	for _, n := range m.nodes {
		known[n.HostName] = n
	}

	for _, p := range st.Tunnels {
		node, ok := known[p.HostName]
		if !ok {
			// 节点已从 VPN Gate 列表消失，用存盘的信息重建
			node = Node{
				HostName:    p.HostName,
				CountryCode: p.CountryCode,
				Country:     p.Country,
			}
		}
		node.Config = p.Config
		// 从旧版本升上来的状态文件没有凭据字段，补一套新的
		cred := SocksCred{User: p.SocksUser, Pass: p.SocksPass}
		if cred.User == "" || cred.Pass == "" {
			gen, err := newSocksCred()
			if err != nil {
				return 0, fmt.Errorf("生成 SOCKS5 凭据失败: %w", err)
			}
			cred = gen
		}
		t := &Tunnel{
			Slot:   p.Slot,
			Port:   p.Port,
			Node:   node,
			Status: "starting",
			Cred:   cred,
		}
		m.mu.Lock()
		m.tunnels[p.Slot] = t
		m.mu.Unlock()
		go m.bringUpPersist(t, true, true)
	}
	return len(st.Tunnels), nil
}
