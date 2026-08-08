package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveVPNGateExit(t *testing.T) {
	if os.Getenv("FANOUT_LIVE_TEST") != "1" {
		t.Skip("FANOUT_LIVE_TEST 未启用")
	}
	bin := os.Getenv("FANOUT_SINGBOX_BIN")
	if bin == "" {
		t.Fatal("FANOUT_SINGBOX_BIN 未设置")
	}
	t.Setenv("PATH", filepath.Dir(bin)+":"+os.Getenv("PATH"))
	nodes, err := fetchNodes(60 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configurePanel(dir)
	defer closePanel()
	m := NewManager(1, dir)
	m.singBoxBin = bin
	tunnel, err := m.Start(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	m.waitUp(tunnel)
	if tunnel.Status != "up" {
		configPath := filepath.Join(dir, "sing-box", tunnel.processName()+".json")
		if output, checkErr := exec.Command(bin, "check", "-c", configPath).CombinedOutput(); checkErr != nil {
			t.Logf("final node=%s config check=%v\n%s", tunnel.Node.HostName, checkErr, output)
		}
		if logData, readErr := os.ReadFile(filepath.Join(dir, "sing-box", tunnel.processName()+".log")); readErr == nil {
			t.Logf("sing-box tunnel log:\n%s", logData)
		}
		t.Fatalf("VPN Gate 出口未连通: %s", tunnel.Err)
	}
	if tunnel.ExitIP == "" {
		t.Fatal("出口 IP 为空")
	}
}
