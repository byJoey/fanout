package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SocksCred is the public credential assigned to one exit.
type SocksCred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Tunnel is one VPN Gate exit. Each tunnel owns an isolated sing-box process
// with a userspace OpenVPN endpoint and a loopback-only SOCKS listener.
type Tunnel struct {
	Slot   int       `json:"slot"`
	Port   int       `json:"port"`
	Node   Node      `json:"node"`
	Status string    `json:"status"` // starting | up | failed | stopped
	ExitIP string    `json:"exit_ip"`
	Err    string    `json:"err,omitempty"`
	Since  time.Time `json:"since"`
	Cred   SocksCred `json:"cred"`

	listener     net.Listener
	endpointPort int
	proc         *singBoxProc
	mu           sync.Mutex
}

func (t *Tunnel) processName() string { return fmt.Sprintf("tunnel-%d", t.Slot) }

func freeLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func (t *Tunnel) startSingBox(bin, workDir string) error {
	t.mu.Lock()
	if t.endpointPort == 0 {
		port, err := freeLoopbackPort()
		if err != nil {
			t.mu.Unlock()
			return fmt.Errorf("分配内部 SOCKS5 端口失败: %w", err)
		}
		t.endpointPort = port
	}
	port := t.endpointPort
	if t.proc == nil {
		dir := filepath.Join(workDir, "sing-box")
		t.proc = &singBoxProc{bin: bin, dir: dir, name: t.processName()}
		t.proc.reapOrphan()
	}
	proc := t.proc
	t.mu.Unlock()

	cfg, err := buildTunnelSingBoxConfig(t.Node.Config, port)
	if err != nil {
		return fmt.Errorf("转换 VPN Gate 配置失败: %w", err)
	}
	cfgPath, err := writeSingBoxConfig(proc.dir, proc.name, cfg)
	if err != nil {
		return fmt.Errorf("写 sing-box 隧道配置失败: %w", err)
	}
	if err := verifySingBoxConfig(bin, cfgPath); err != nil {
		return err
	}
	return proc.start(cfgPath)
}

func (t *Tunnel) stopEngine() {
	t.mu.Lock()
	proc := t.proc
	t.mu.Unlock()
	if proc != nil {
		proc.stop()
	}
}

func (t *Tunnel) internalProxyAddr() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.endpointPort == 0 || t.proc == nil || t.proc.exited() {
		return "", fmt.Errorf("OpenVPN endpoint 未运行")
	}
	return fmt.Sprintf("127.0.0.1:%d", t.endpointPort), nil
}

func (t *Tunnel) internalProxyPort() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.endpointPort
}

func (t *Tunnel) dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("只支持 TCP")
	}
	proxyAddr, err := t.internalProxyAddr()
	if err != nil {
		return nil, err
	}
	return dialSOCKS5(proxyAddr, addr, 20*time.Second)
}

// serve keeps the public SOCKS5 socket in fanout so credentials can be changed
// without restarting the OpenVPN endpoint.
func (t *Tunnel) serve() error {
	var ln net.Listener
	var err error
	for i := 0; i < 6; i++ {
		ln, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", t.Port))
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		port, perr := freeRandomPort(map[int]bool{t.Port: true})
		if perr != nil {
			return fmt.Errorf("监听 %d 失败且无备用端口: %w", t.Port, err)
		}
		ln, err = net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			return fmt.Errorf("监听 %d 失败: %w", port, err)
		}
		t.Port = port
	}
	t.mu.Lock()
	t.listener = ln
	t.mu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			cred := t.credential()
			go serveSocks(conn, &cred, t.dial)
		}
	}()
	return nil
}

func (t *Tunnel) credential() SocksCred {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Cred
}

func (t *Tunnel) setCredential(c SocksCred) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Cred = c
}

func (t *Tunnel) probeExitIP(timeout time.Duration) (string, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return t.dial(network, addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	resp, err := client.Get("http://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("查询出口 IP 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("查询出口 IP 返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("读取出口 IP 失败: %w", err)
	}
	ip := strings.TrimSpace(string(body))
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("出口 IP 返回异常: %q", ip)
	}
	return ip, nil
}

func (t *Tunnel) waitExitIP(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if ip, err := t.probeExitIP(6 * time.Second); err == nil {
			return ip, nil
		} else {
			lastErr = err
		}
		t.mu.Lock()
		proc := t.proc
		t.mu.Unlock()
		if proc == nil {
			return "", fmt.Errorf("sing-box 隧道进程未启动")
		}
		if proc.exited() {
			return "", fmt.Errorf("sing-box 隧道进程已退出，详见 %s", filepath.Join(proc.dir, proc.name+".log"))
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("等待 OpenVPN endpoint 就绪超时: %w", lastErr)
}

func (t *Tunnel) stop() {
	t.mu.Lock()
	ln := t.listener
	t.listener = nil
	t.Status = "stopped"
	t.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	t.stopEngine()
}
