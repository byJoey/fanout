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
	TemplateID int // 入站模板；0 表示只开隧道不建入站
}

// Provision 异步执行一次批量开出口，立刻返回作业句柄供界面轮询。
//
// 隧道并行拉起（每条都要等 OpenVPN 握手，串行会线性累加等待），
// 入站复制统一放在最后串行执行，因为每次都会重启 sing-box 网关。
func (m *Manager) Provision(req ProvisionRequest) (*Job, error) {
	if req.Count < 1 {
		return nil, fmt.Errorf("数量至少为 1")
	}
	picks, err := m.pickNodes(req.Region, req.Count)
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

	where := req.Region
	if where == "" {
		where = "任意地区"
	}
	job := m.jobs.New(fmt.Sprintf("开 %d 个 %s 出口", len(picks), where), labels)

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
// 每个节点等 OpenVPN endpoint 最长 40 秒，所以这里给足余量。
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
func (m *Manager) pickNodes(region string, count int) ([]Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	used := map[string]bool{}
	for _, t := range m.tunnels {
		used[t.Node.HostName] = true
	}

	var out []Node
	for _, n := range m.nodes {
		if len(out) >= count {
			break
		}
		if used[n.HostName] {
			continue
		}
		if region != "" && !strings.EqualFold(n.CountryCode, region) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		if region != "" {
			return nil, fmt.Errorf("%s 没有可用的空闲节点", region)
		}
		return nil, fmt.Errorf("没有可用的空闲节点，试试重新拉取列表")
	}
	return out, nil
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
	for _, n := range m.nodes {
		if used[n.HostName] || n.CountryCode == "" {
			continue
		}
		s := byCode[n.CountryCode]
		if s == nil {
			s = &RegionStat{Code: n.CountryCode, Name: n.Country, BestPing: n.Ping}
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
	if n.CountryCode != "" {
		return n.CountryCode
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
