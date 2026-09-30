package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 换节点未收尾的标记要跟着状态一起落盘。
//
// 不存的话，重启后隧道是新节点、入站还绑着旧节点，两边对不上，
// 那个入站就掉成没人认领的孤儿，流量悄悄走直连。
func TestSaveStateKeepsPrevHost(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(20, dir)
	tn := &Tunnel{
		Slot: 1, Port: 12345,
		Node:   Node{HostName: "vpn-new", CountryCode: "JP"},
		Status: "starting",
		Cred:   SocksCred{User: "u", Pass: "p"},
	}
	tn.setPrevHost("vpn-old")
	m.tunnels[1] = tn

	if err := m.saveState(); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st persistedState
	if err := json.Unmarshal(blob, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Tunnels) != 1 {
		t.Fatalf("应当存下 1 条，实际 %d", len(st.Tunnels))
	}
	if st.Tunnels[0].PrevHost != "vpn-old" {
		t.Fatalf("没存下换节点前绑的节点，实际 %q", st.Tunnels[0].PrevHost)
	}
	if st.Tunnels[0].HostName != "vpn-new" {
		t.Fatalf("当前节点应当是新的，实际 %q", st.Tunnels[0].HostName)
	}
}

// 收尾之后标记要清掉，否则每次重启都会白做一次改绑。
func TestPrevHostClearedAfterSettle(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(20, dir)
	tn := &Tunnel{Slot: 1, Node: Node{HostName: "vpn-new"}, Status: "up"}
	tn.setPrevHost("vpn-old")
	m.tunnels[1] = tn
	if err := m.saveState(); err != nil {
		t.Fatal(err)
	}

	tn.setPrevHost("")
	if err := m.saveState(); err != nil {
		t.Fatal(err)
	}
	blob, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	var st persistedState
	if err := json.Unmarshal(blob, &st); err != nil {
		t.Fatal(err)
	}
	if st.Tunnels[0].PrevHost != "" {
		t.Fatalf("收尾后标记该清掉，实际 %q", st.Tunnels[0].PrevHost)
	}
	// omitempty：清掉之后不该再出现在文件里
	if got := string(blob); containsStr(got, "prev_host") {
		t.Fatalf("清掉之后字段不该还在文件里: %s", got)
	}
}

// 恢复时要把标记读回来，否则自愈逻辑根本不会触发。
func TestRestoreStateReadsPrevHost(t *testing.T) {
	dir := t.TempDir()
	blob := `{"tunnels":[{"slot":1,"port":12345,"hostname":"vpn-new","country_code":"JP","config":"x","socks_user":"u","socks_pass":"p","prev_host":"vpn-old"}]}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(blob), 0600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(20, dir)
	// 不让它真去拉隧道：restoreTunnel 会调 bringUpPersist，
	// 这里只关心状态读没读对，所以读完立刻看字段。
	n, err := m.restoreState()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应当恢复 1 条，实际 %d", n)
	}
	m.mu.RLock()
	tn := m.tunnels[1]
	m.mu.RUnlock()
	if tn == nil {
		t.Fatal("隧道没恢复出来")
	}
	if got := tn.prevHostOf(); got != "vpn-old" {
		t.Fatalf("没读回换节点标记，实际 %q", got)
	}
	// 收尾：别让后台的 bringUpPersist 继续折腾
	tn.Status = "stopped"
}

// 老版本的状态文件里没有这个字段，读出来该是空的，不能误触发改绑。
func TestRestoreStateOldFormatHasNoPrevHost(t *testing.T) {
	dir := t.TempDir()
	blob := `{"tunnels":[{"slot":1,"port":12345,"hostname":"vpn-a","country_code":"JP","config":"x","socks_user":"u","socks_pass":"p"}]}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(blob), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(20, dir)
	if _, err := m.restoreState(); err != nil {
		t.Fatal(err)
	}
	m.mu.RLock()
	tn := m.tunnels[1]
	m.mu.RUnlock()
	if got := tn.prevHostOf(); got != "" {
		t.Fatalf("老格式不该带标记，实际 %q", got)
	}
	tn.Status = "stopped"
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
