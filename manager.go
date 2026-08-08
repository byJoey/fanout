package main

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// Manager 维护所有隧道，负责分配槽位与端口。
type Manager struct {
	mu         sync.RWMutex
	tunnels    map[int]*Tunnel
	nodes      []Node
	fetched    time.Time
	workDir    string
	singBoxBin string
	maxSlots   int
	jobs       JobStore
}

func NewManager(maxSlots int, workDir string, binary ...string) *Manager {
	m := &Manager{
		tunnels:  map[int]*Tunnel{},
		workDir:  workDir,
		maxSlots: maxSlots,
	}
	if len(binary) > 0 && binary[0] != "" {
		m.singBoxBin, _ = findSingBox(workDir, binary...)
	} else {
		m.singBoxBin, _ = findSingBox(workDir)
	}
	return m
}

// RefreshNodes 重新拉取节点列表。
func (m *Manager) RefreshNodes() (int, error) {
	nodes, err := fetchNodes(60 * time.Second)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.nodes = nodes
	m.fetched = time.Now()
	m.mu.Unlock()
	return len(nodes), nil
}

func (m *Manager) Nodes() ([]Node, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Node, len(m.nodes))
	copy(out, m.nodes)
	return out, m.fetched
}

func (m *Manager) Tunnels() []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

// freeSlot 找一个未占用的槽位。槽位同时决定端口与网段。
func (m *Manager) freeSlot() (int, error) {
	for i := 1; i <= m.maxSlots; i++ {
		if _, used := m.tunnels[i]; !used {
			return i, nil
		}
	}
	return 0, fmt.Errorf("槽位已满（上限 %d）", m.maxSlots)
}

// Start 为指定节点开一条隧道，返回分配到的本地端口。
func (m *Manager) Start(node Node) (*Tunnel, error) {
	m.mu.Lock()
	slot, err := m.freeSlot()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	// 端口随机取，避免固定规律撞上机器上的其他服务
	taken := map[int]bool{}
	for _, other := range m.tunnels {
		taken[other.Port] = true
	}
	port, err := freeRandomPort(taken)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	cred, err := newSocksCred()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	t := &Tunnel{
		Slot:   slot,
		Port:   port,
		Node:   node,
		Status: "starting",
		Since:  time.Now(),
		Cred:   cred,
	}
	m.tunnels[slot] = t
	m.mu.Unlock()

	go m.bringUp(t, true)
	return t, nil
}

// bringUp 把一条隧道拉起来。
//
// notify 决定成功后是否立刻重建后端配置。换节点重连时要传 false：
// 那条路径随后会调 rebind/resync 把入站改绑到新节点，在那之前重建配置
// 会因为入站还指着旧节点名而把路由规则丢掉。
func (m *Manager) bringUp(t *Tunnel, notify bool) {
	m.bringUpPersist(t, notify, false)
}

// 自动重连的退避区间：一轮候选全挂后等一会儿再刷新节点列表重来，
// 别把死节点列表打爆，也别让恢复拖太久。
const (
	reconnectBackoffMin = 5 * time.Second
	reconnectBackoffMax = 60 * time.Second
)

// bringUpPersist 把一条隧道拉起来。
//
// persist=false（手动新建）：走一轮候选，全失败就标 failed，让用户能立刻看到并重试。
// persist=true（自动重连 / 重启恢复）：一轮全失败不放弃，退避后刷新节点列表再来一轮，
// 一直循环到连上或这条隧道被用户停掉。VPN Gate 死节点多，"当前都不可用"往往只是
// 这一批候选恰好都挂了，过一会儿就有新节点，不该让出口永久躺死。
func (m *Manager) bringUpPersist(t *Tunnel, notify bool, persist bool) {
	backoff := reconnectBackoffMin
	for {
		if m.tryCandidates(t, notify) {
			return
		}
		// 隧道已被用户停掉或从管理器移除，别再重试
		if !persist || !m.tunnelActive(t) {
			if persist {
				return
			}
			t.Status = "failed"
			if serr := m.saveState(); serr != nil {
				log.Printf("保存状态失败: %v", serr)
			}
			return
		}

		t.Status = "starting"
		t.Err = fmt.Sprintf("暂无可用节点，%.0f 秒后重试", backoff.Seconds())
		log.Printf("隧道 %d 一轮候选均失败，%.0f 秒后刷新节点重试", t.Slot, backoff.Seconds())
		time.Sleep(backoff)
		if !m.tunnelActive(t) {
			return
		}
		if _, err := m.RefreshNodes(); err != nil {
			log.Printf("重试前刷新节点列表失败: %v", err)
		}
		if backoff < reconnectBackoffMax {
			backoff *= 2
			if backoff > reconnectBackoffMax {
				backoff = reconnectBackoffMax
			}
		}
	}
}

// tryCandidates 走一轮候选节点，成功返回 true。失败不改 Status（留给调用方决定）。
func (m *Manager) tryCandidates(t *Tunnel, notify bool) bool {
	// VPN Gate 是志愿者节点，列表里有相当比例已下线或满员（AUTH_FAILED），
	// 连不上就顺着候选列表换下一个，不必让用户手动试。
	candidates := m.candidatesFor(t.Node)
	for i, node := range candidates {
		if !m.tunnelActive(t) {
			return false
		}
		// 其他隧道可能在重试期间占用了这个节点，跳过以免多个端口撞同一出口 IP
		if i > 0 && m.nodeInUse(node.HostName, t.Slot) {
			continue
		}
		t.Node = node
		t.Status = "starting"
		if i > 0 {
			t.Err = fmt.Sprintf("已换到第 %d 个候选节点", i+1)
		}

		err := m.tryNode(t)
		if err == nil {
			t.Status = "up"
			t.Err = ""
			if serr := m.saveState(); serr != nil {
				log.Printf("保存状态失败: %v", serr)
			}
			if notify {
				m.notifyPanel()
			}
			return true
		}
		t.Err = err.Error()
		t.stopEngine()
	}
	return false
}

// tunnelActive 判断这条隧道是否还归管理器所有且未被用户停掉。
// 用指针比对：Stop 会从 map 里删除并把 Status 置 stopped，
// 重连循环据此退出，避免对着一条已经不存在的隧道空转。
func (m *Manager) tunnelActive(t *Tunnel) bool {
	if t.Status == "stopped" {
		return false
	}
	m.mu.RLock()
	cur, ok := m.tunnels[t.Slot]
	m.mu.RUnlock()
	return ok && cur == t
}

// tryNode 尝试用当前节点把隧道拉起来。
func (m *Manager) tryNode(t *Tunnel) error {
	if m.singBoxBin == "" {
		return fmt.Errorf("sing-box 不可用")
	}
	if err := t.startSingBox(m.singBoxBin, m.workDir); err != nil {
		return err
	}
	if t.listener == nil {
		if err := t.serve(); err != nil {
			return err
		}
	}
	ip, err := t.waitExitIP(40 * time.Second)
	if err != nil {
		return err
	}
	t.ExitIP = ip
	return nil
}

// candidatesFor 以指定节点打头，后面跟上同地区的其他节点作为备选。
func (m *Manager) candidatesFor(first Node) []Node {
	const maxTries = 6
	m.mu.RLock()
	defer m.mu.RUnlock()

	used := map[string]bool{first.HostName: true}
	for _, t := range m.tunnels {
		used[t.Node.HostName] = true
	}

	// 地区决定了备选范围，缺失时先从当前列表补一次，
	// 否则会退化成"任意地区都算同区"。
	region := first.CountryCode
	if region == "" {
		for _, n := range m.nodes {
			if n.HostName == first.HostName {
				region = n.CountryCode
				break
			}
		}
	}

	out := []Node{first}
	for _, n := range m.nodes {
		if len(out) >= maxTries {
			break
		}
		if used[n.HostName] {
			continue
		}
		// 地区实在拿不到时不做限制，总比连不上强
		if region != "" && n.CountryCode != region {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Stop 停掉一条隧道并释放槽位。
func (m *Manager) Stop(slot int) error {
	invalidateInbounds()
	m.mu.Lock()
	t, ok := m.tunnels[slot]
	if ok {
		delete(m.tunnels, slot)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}
	t.stop()
	if err := m.saveState(); err != nil {
		log.Printf("保存状态失败: %v", err)
	}
	m.notifyPanel()
	return nil
}

// Swap 把一条隧道换到同地区的另一个节点上，端口与已分发的客户端配置保持不变。
//
// 与健康检查的自动重连不同：那边优先重连原节点（目标是恢复），
// 这里用户是嫌当前出口 IP 不好用，必须真的换一个。
func (m *Manager) Swap(slot int) error {
	m.mu.RLock()
	t, ok := m.tunnels[slot]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}
	if t.Status == "starting" {
		return fmt.Errorf("这个出口正在连接中，稍等一下")
	}

	// pickNodes 已排除所有在用节点，拿到的必然不是当前这个
	picks, err := m.pickNodes(t.Node.CountryCode, 1)
	if err != nil {
		return err
	}
	oldHost := t.Node.HostName
	t.Node = picks[0]
	m.reconnect(t, oldHost)
	return nil
}

// StopAll 停掉所有隧道并清空状态文件。
func (m *Manager) StopAll() {
	for _, t := range m.Tunnels() {
		_ = m.Stop(t.Slot)
	}
}

// SetCred 改一条出口的 SOCKS5 凭据。cred 两个字段都为空表示随机重置。
// The sing-box gateway carries the same SOCKS credential, so it must be
// regenerated after a credential change.
func (m *Manager) SetCred(slot int, cred SocksCred) (SocksCred, error) {
	m.mu.RLock()
	t, ok := m.tunnels[slot]
	m.mu.RUnlock()
	if !ok {
		return SocksCred{}, fmt.Errorf("槽位 %d 没有运行中的隧道", slot)
	}

	if cred.User == "" && cred.Pass == "" {
		gen, err := newSocksCred()
		if err != nil {
			return SocksCred{}, err
		}
		cred = gen
	}
	if err := validateCred(cred); err != nil {
		return SocksCred{}, err
	}

	t.setCredential(cred)
	if err := m.saveState(); err != nil {
		log.Printf("保存状态失败: %v", err)
	}
	m.syncCred(t)
	return cred, nil
}

// syncCred 把新凭据写进后端的 socks 出站。
func (m *Manager) syncCred(t *Tunnel) {
	if err := m.resync(t); err != nil {
		log.Printf("同步 SOCKS5 凭据到节点链接后端失败: %v", err)
	}
}

// Shutdown 停掉运行态但保留状态文件，让下次启动能恢复同样的隧道。
func (m *Manager) Shutdown() {
	for _, t := range m.Tunnels() {
		t.stop()
	}
}

// nodeInUse 判断某节点是否已被别的隧道占用。
func (m *Manager) nodeInUse(host string, exceptSlot int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for slot, t := range m.tunnels {
		if slot != exceptSlot && t.Node.HostName == host {
			return true
		}
	}
	return false
}

// rebind moves inbound routing to a replacement exit.
func (m *Manager) rebind(oldHost string, t *Tunnel) error {
	x, err := openPanel()
	if err != nil {
		return nil
	}
	return x.Rebind(oldHost, t, m.Tunnels())
}

// resync refreshes the sing-box SOCKS outbound after reconnecting the same exit.
func (m *Manager) resync(t *Tunnel) error {
	x, err := openPanel()
	if err != nil {
		return nil
	}
	return x.ResyncOutbound(t, m.Tunnels())
}

// notifyPanel 告诉后端隧道集合变了。
//
// Gateway outbounds are derived from the live tunnel list. Failure to refresh
// should not make the underlying tunnel operation fail.
func (m *Manager) notifyPanel() {
	p, err := openPanel()
	if err != nil {
		return
	}
	if err := p.OnTunnelsChanged(m.Tunnels()); err != nil {
		log.Printf("同步节点链接后端失败: %v", err)
	}
}
