package main

import (
	"sync"
)

// Panel 是 fanout 管理节点链接的后端。
//
// The only implementation is Native, backed by sing-box.
type Panel interface {
	// Kind is used by the web UI to describe the active backend.
	Kind() string
	// Describe 给出一行人能读的后端说明。
	Describe() string

	Inbounds(live map[string]bool) ([]Inbound, error)
	InboundDetail(id int, publicHost string) (*InboundDetail, error)
	InboundLinks(ids []int, publicHost string) ([]string, error)

	Bind(inboundTag string, hostname string, tunnels []*Tunnel) error
	Rebind(oldHost string, target *Tunnel, tunnels []*Tunnel) error
	ResyncOutbound(t *Tunnel, tunnels []*Tunnel) error

	CloneToTunnels(templateID int, hosts []string, tunnels []*Tunnel) ([]int, error)
	DeleteInbounds(ids []int, tunnels []*Tunnel) error

	// CreateInbound creates an inbound and rebuilds the sing-box gateway.
	CreateInbound(spec NewInboundSpec, tunnels []*Tunnel) (*CreatedInbound, error)

	// UpdateInbound 改端口、备注与启停。只有非零/非 nil 的字段会被写入。
	UpdateInbound(id int, patch InboundPatch, tunnels []*Tunnel) error

	// AddClient 给入站加一个客户端，email 留空时自动命名。
	AddClient(id int, email string, tunnels []*Tunnel) error
	// DeleteClient 摘掉入站上的一个客户端。
	DeleteClient(id int, email string, tunnels []*Tunnel) error
	// ResetClient 换掉客户端的凭据（UUID / trojan 密码），已分发的旧链接随即失效。
	ResetClient(id int, email string, tunnels []*Tunnel) error

	// OnTunnelsChanged rebuilds the gateway outbounds after tunnel changes.
	OnTunnelsChanged(tunnels []*Tunnel) error

	// Close releases the sing-box gateway process.
	Close()
}

// InboundPatch 描述对入站的一次局部修改。指针为 nil 表示该字段不动。
type InboundPatch struct {
	Port   *int
	Remark *string
	Enable *bool
}

// CreatedInbound 是新建入站后回给界面的摘要。
type CreatedInbound struct {
	ID       int    `json:"id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Remark   string `json:"remark"`
	Network  string `json:"network"`
	Security string `json:"security"`
}

// closePanel 在进程退出时释放后端资源。
func closePanel() {
	panelState.mu.Lock()
	p := panelState.current
	panelState.mu.Unlock()
	if p != nil {
		p.Close()
	}
}

// panelState caches the sing-box gateway backend.
var panelState struct {
	mu         sync.Mutex
	current    Panel
	workDir    string
	listenAddr string
}

func configurePanel(workDir string) {
	configurePanelWithListen(workDir, "0.0.0.0")
}

func configurePanelWithListen(workDir, listenAddr string) {
	panelState.mu.Lock()
	defer panelState.mu.Unlock()
	panelState.workDir = workDir
	panelState.listenAddr = listenAddr
	panelState.current = nil
}

// openPanel returns the local sing-box gateway backend.
func openPanel() (Panel, error) {
	panelState.mu.Lock()
	defer panelState.mu.Unlock()

	if panelState.current != nil {
		return panelState.current, nil
	}

	n, err := openNative(panelState.workDir, panelState.listenAddr)
	if err != nil {
		return nil, err
	}
	panelState.current = n
	return n, nil
}
