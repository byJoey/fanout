package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProvisionRequest 是"给我 N 个某地区的出口"这个意图。
type ProvisionRequest struct {
	Region     string // 国家码，空表示不限
	Count      int
	TemplateID int // 3x-ui 入站模板；0 表示只开隧道不建入站
	// EveryRegion 表示每个有节点的国家都来 Count 个，此时 Region 被忽略。
	EveryRegion bool
}

// Provision 异步执行一次批量开出口，立刻返回作业句柄供界面轮询。
//
// 隧道并行拉起（每条都要等 openvpn 握手，串行会线性累加等待），
// 面板侧的入站创建则统一放到最后串行做一次，因为每次改路由都要重启 Xray。
func (m *Manager) Provision(req ProvisionRequest) (*Job, error) {
	if req.Count < 1 {
		return nil, fmt.Errorf("数量至少为 1")
	}
	var picks []Node
	var err error
	if req.EveryRegion {
		picks, err = m.pickEveryRegion(req.Count)
	} else {
		picks, err = m.pickNodes(req.Region, req.Count, nil)
	}
	if err != nil {
		return nil, err
	}

	labels := make([]string, 0, len(picks)+1)
	for _, n := range picks {
		labels = append(labels, regionLabel(n)+" 出口")
	}
	if req.TemplateID > 0 {
		labels = append(labels, "创建节点链接")
	}

	title := ""
	switch {
	case req.EveryRegion:
		title = fmt.Sprintf("每个国家开 %d 个，共 %d 条出口", req.Count, len(picks))
	case req.Region != "":
		title = fmt.Sprintf("开 %d 个 %s 出口", len(picks), req.Region)
	default:
		title = fmt.Sprintf("开 %d 个任意地区出口", len(picks))
	}
	job := m.jobs.New(title, labels)

	go m.runProvision(job, picks, req.TemplateID)
	return job, nil
}

func (m *Manager) runProvision(job *Job, picks []Node, templateID int) {
	defer job.Finish()

	var wg sync.WaitGroup
	started := make([]*Tunnel, len(picks))

	for i, node := range picks {
		t, err := m.Start(node)
		if err != nil {
			job.Set(i, "failed", err.Error())
			continue
		}
		started[i] = t
		job.Set(i, "running", "正在连接 "+node.HostName)

		wg.Add(1)
		go func(i int, t *Tunnel) {
			defer wg.Done()
			m.waitUp(t)
			if t.Status == "up" {
				job.Set(i, "ok", t.ExitIP)
				return
			}
			job.Set(i, "failed", firstLine(t.Err))
		}(i, t)
	}
	wg.Wait()

	if templateID <= 0 {
		return
	}

	step := len(picks)
	var hosts []string
	for _, t := range started {
		if t != nil && t.Status == "up" {
			hosts = append(hosts, t.Node.HostName)
		}
	}
	if len(hosts) == 0 {
		job.Set(step, "failed", "没有连通的出口，跳过")
		return
	}

	job.Set(step, "running", fmt.Sprintf("为 %d 个出口建入站", len(hosts)))
	x, err := openPanel()
	if err != nil {
		job.Set(step, "failed", err.Error())
		return
	}
	ports, err := x.CloneToTunnels(templateID, hosts, m.Tunnels())
	invalidateInbounds()
	if err != nil {
		job.Set(step, "failed", firstLine(err.Error()))
		return
	}
	job.Set(step, "ok", fmt.Sprintf("已创建 %d 个入站", len(ports)))
}

// waitUp 等一条隧道跑完 bringUp。bringUp 最多试 6 个候选节点，
// 每个节点等 tun0 最长 40 秒，所以这里给足余量。
func (m *Manager) waitUp(t *Tunnel) {
	const maxWait = 5 * time.Minute
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if t.Status == "up" || t.Status == "failed" || t.Status == "stopped" {
			return
		}
		time.Sleep(time.Second)
	}
}

// pickNodes 按地区挑 count 个还没被占用的节点，速度优先。
//
// avoid 里的 hostname 一并跳过，用于"换节点"：那条路径要避开这条出口
// 之前用过的节点，否则连点两次会在两个节点之间来回跳。传 nil 表示不额外排除。
func (m *Manager) pickNodes(region string, count int, avoid map[string]bool) ([]Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	used := map[string]bool{}
	for _, t := range m.tunnels {
		used[t.Node.HostName] = true
	}

	pool := m.nodePoolLocked()
	var out []Node
	for _, n := range pool {
		if len(out) >= count {
			break
		}
		if used[n.HostName] || avoid[n.HostName] {
			continue
		}
		if region != "" && !strings.EqualFold(n.CountryCode, region) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, m.noNodesErrLocked(region, len(pool) < len(m.nodes))
	}
	return out, nil
}

// pickEveryRegion 给每个有空闲节点的国家各挑 perRegion 个。
//
// 一次挑完而不是按地区循环调 pickNodes：那样每轮都读同一份 m.tunnels，
// 挑出来的会重复（隧道还没开起来，避让集合不会变）。
// 总数受槽位上限约束，排不下时按地区可用数从多到少截断，
// 保证先把节点多的大区开出来。
func (m *Manager) pickEveryRegion(perRegion int) ([]Node, error) {
	if perRegion < 1 {
		perRegion = 1
	}

	m.mu.RLock()
	used := map[string]bool{}
	for _, t := range m.tunnels {
		used[t.Node.HostName] = true
	}
	room := m.maxSlots - len(m.tunnels)
	// 上限可以在面板上随时改，所以得在锁里取一份，不能等解锁后再读
	maxSlots := m.maxSlots
	pool := m.nodePoolLocked()
	filtered := len(pool) < len(m.nodes)

	// pool 本身按速度降序，所以每个地区先遇到的就是最快的
	byRegion := map[string][]Node{}
	var order []string
	for _, n := range pool {
		if used[n.HostName] || n.CountryCode == "" {
			continue
		}
		code := strings.ToUpper(n.CountryCode)
		if len(byRegion[code]) == 0 {
			order = append(order, code)
		}
		if len(byRegion[code]) < perRegion {
			byRegion[code] = append(byRegion[code], n)
		}
	}
	m.mu.RUnlock()

	if len(order) == 0 {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return nil, m.noNodesErrLocked("", filtered)
	}
	if room <= 0 {
		return nil, fmt.Errorf("槽位已满（上限 %d），可在设置里调大，或者先停几个出口再来", maxSlots)
	}

	// 节点多的地区排前面：装不下时优先保住选择面大的那些
	sort.Slice(order, func(i, j int) bool {
		if len(byRegion[order[i]]) != len(byRegion[order[j]]) {
			return len(byRegion[order[i]]) > len(byRegion[order[j]])
		}
		return order[i] < order[j]
	})

	var out []Node
	for _, code := range order {
		for _, n := range byRegion[code] {
			if len(out) >= room {
				return out, nil
			}
			out = append(out, n)
		}
	}
	return out, nil
}

// noNodesErrLocked 拼一句能照着做的错误。调用方必须已持 m.mu。
//
// 挑不到节点有好几种原因，报一句笼统的"没有可用节点"会让人无从下手：
// 家宽过滤剔掉了一批、这个地区本来就没有、列表过期了，处理方式完全不同。
func (m *Manager) noNodesErrLocked(region string, filtered bool) error {
	tail := ""
	if filtered && residentialOnly() {
		tail = "；现在只用家宽节点，想放开就去设置里关掉「只用家宽」"
	}
	if region != "" {
		return fmt.Errorf("%s 没有可用的空闲节点%s", region, tail)
	}
	return fmt.Errorf("没有可用的空闲节点，试试重新拉取列表%s", tail)
}

// nodePoolLocked 返回可以拿来挑的节点。开了"只用家宽"就把 vpngate
// 自营机房的节点剔掉。调用方必须已持 m.mu。
//
// 只影响"新挑节点"：已经跑起来的隧道不会因为打开这个开关而被换掉，
// 否则改一下设置就把用户手上所有出口的 IP 全换了。
func (m *Manager) nodePoolLocked() []Node {
	if !residentialOnly() {
		return m.nodes
	}
	out := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		if n.Residential {
			out = append(out, n)
		}
	}
	return out
}

// RegionStat 是某个地区的可用节点概况，用于新建向导里的地区选择。
type RegionStat struct {
	Code      string  `json:"code"`
	Name      string  `json:"name"`
	Available int     `json:"available"`
	BestPing  int     `json:"best_ping"`
	BestSpeed float64 `json:"best_speed_mbps"`
}

// Regions 汇总各地区还剩多少空闲节点，按可用数量降序。
func (m *Manager) Regions() []RegionStat {
	m.mu.RLock()
	defer m.mu.RUnlock()

	used := map[string]bool{}
	for _, t := range m.tunnels {
		used[t.Node.HostName] = true
	}

	byCode := map[string]*RegionStat{}
	for _, n := range m.nodePoolLocked() {
		if used[n.HostName] || n.CountryCode == "" {
			continue
		}
		s := byCode[n.CountryCode]
		if s == nil {
			s = &RegionStat{Code: n.CountryCode, Name: countryLabel(n.CountryCode, n.Country), BestPing: n.Ping}
			byCode[n.CountryCode] = s
		}
		s.Available++
		if n.SpeedMbps > s.BestSpeed {
			s.BestSpeed = n.SpeedMbps
		}
		if n.Ping > 0 && (s.BestPing == 0 || n.Ping < s.BestPing) {
			s.BestPing = n.Ping
		}
	}

	out := make([]RegionStat, 0, len(byCode))
	for _, s := range byCode {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Available != out[j].Available {
			return out[i].Available > out[j].Available
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// regionLabel 给出口起一个人能读的名字。
func regionLabel(n Node) string {
	if place := nodeLabel(n); place != "" {
		return place
	}
	return n.HostName
}

// firstLine 截取错误的第一行，界面里放得下。
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
