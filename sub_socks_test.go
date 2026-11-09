package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// socksSubTunnel 造一条已连上的出口隧道。
func socksSubTunnel(slot, port int, country, code, exitIP string) *Tunnel {
	return &Tunnel{
		Slot:   slot,
		Port:   port,
		Node:   Node{HostName: "vpn-" + code, Country: country, CountryCode: code},
		Status: "up",
		Cred:   SocksCred{User: "fo" + code + "user", Pass: "pass-" + code},
		ExitIP: exitIP,
	}
}

// SOCKS5 订阅也要挂在访问路径下面，那层门槛不能因为新加了端点就漏掉。
func TestSocksPathUnderBasePath(t *testing.T) {
	dir := t.TempDir()
	if _, err := initBasePath(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := setBasePath("myPath"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = setBasePath("") })
	if got := socksPath("tok123"); got != "/myPath/socks?token=tok123" {
		t.Fatalf("socksPath=%q", got)
	}
}

// 口令不对就当这地址不存在。
func TestHandleSocksSubWrongTokenIs404(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	h := handleSocksSub(m)

	for _, q := range []string{"", "?token=", "?token=猜的"} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/socks"+q, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("token=%q 应当 404，实际 %d", q, rec.Code)
		}
	}
}

// 没有出口时回 404 而不是空正文：客户端拿到空订阅会把已有节点清光。
func TestHandleSocksSubEmptyIsNotEmptyBody(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet, "/socks?token="+tok, nil))
	if rec.Code == http.StatusOK {
		t.Fatal("一个出口都没有时不能回 200 空正文")
	}
}

// 正常路径：每个可用出口一条 socks5:// ，整份 base64。
func TestHandleSocksSubListsUpExits(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	m.tunnels[1] = socksSubTunnel(1, 23011, "Japan", "JP", "1.2.3.243")
	m.tunnels[2] = socksSubTunnel(2, 23012, "United States", "US", "5.6.7.111")
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet, "/socks?token="+tok+"&host=9.9.9.9", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 %d，正文 %s", rec.Code, rec.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("默认应当是 base64: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "socks5://foJPuser:pass-JP@9.9.9.9:23011") {
		t.Fatalf("少了日本出口: %q", body)
	}
	if !strings.Contains(body, "socks5://foUSuser:pass-US@9.9.9.9:23012") {
		t.Fatalf("少了美国出口: %q", body)
	}
	if got := rec.Header().Get("Profile-Update-Interval"); got != "1" {
		t.Fatalf("少了客户端自动更新间隔: %q", got)
	}
}

// 连接中和停掉的隧道不进口：端口还没通，客户端拿到也是连不上。
func TestHandleSocksSubSkipsNotUpExits(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	m.tunnels[1] = socksSubTunnel(1, 23011, "Japan", "JP", "1.2.3.243")
	m.tunnels[2] = socksSubTunnel(2, 23012, "Korea", "KR", "5.6.7.111")
	m.tunnels[2].Status = "starting"
	m.tunnels[3] = socksSubTunnel(3, 23013, "China", "CN", "8.8.8.8")
	m.tunnels[3].Status = "stopped"
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet,
		"/socks?token="+tok+"&host=9.9.9.9&target=links", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "23011") {
		t.Fatalf("可用出口不该漏: %q", body)
	}
	if strings.Contains(body, "23012") || strings.Contains(body, "23013") {
		t.Fatalf("未连上的出口不该进订阅: %q", body)
	}
}

// 明文格式：一行一条 socks5:// 。
func TestHandleSocksSubPlainTarget(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	m.tunnels[1] = socksSubTunnel(1, 23011, "Japan", "JP", "1.2.3.243")
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet,
		"/socks?token="+tok+"&host=9.9.9.9&target=links", nil))
	body := rec.Body.String()
	if !strings.HasPrefix(body, "socks5://") {
		t.Fatalf("target=links 应当出明文: %q", body)
	}
}

// Clash 配置：得有 proxies、proxy-groups 和 rules，缺一段客户端就不认。
func TestHandleSocksSubClashTarget(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	m.tunnels[1] = socksSubTunnel(1, 23011, "Japan", "JP", "1.2.3.243")
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet,
		"/socks?token="+tok+"&host=9.9.9.9&target=clash", nil))
	body := rec.Body.String()
	for _, want := range []string{"proxies:", "proxy-groups:", "rules:", "type: socks5",
		"server: \"9.9.9.9\"", "port: 23011", "username: \"foJPuser\"", "password: \"pass-JP\""} {
		if !strings.Contains(body, want) {
			t.Fatalf("Clash 配置少了 %q:\n%s", want, body)
		}
	}
}

// socks5:// 这个格式本身没有名字字段，客户端只显示地址和端口。
// 别名得挂在 URI 的 # 后面，认这个约定的客户端就会拿它当节点名。
func TestHandleSocksSubCarriesAlias(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	m.tunnels[1] = socksSubTunnel(1, 23011, "Japan", "JP", "1.2.3.243")
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet,
		"/socks?token="+tok+"&host=9.9.9.9&target=links", nil))
	body := rec.Body.String()
	want := "socks5://foJPuser:pass-JP@9.9.9.9:23011#🇯🇵%20日本%20·%20vpn-JP"
	if !strings.Contains(body, want) {
		t.Fatalf("订阅里应当带别名片段:\n%s", body)
	}
}

// 别名里会破坏解析的字符要转义，国旗和中文原样留着。
func TestSocksSubEscape(t *testing.T) {
	if got := socksSubEscape("🇯🇵 日本 243"); got != "🇯🇵%20日本%20243" {
		t.Fatalf("转义不对: %q", got)
	}
	if got := socksSubEscape("a#b%c"); got != "a%23b%25c" {
		t.Fatalf("转义不对: %q", got)
	}
}

func TestHandleSocksSubRejectsUnknownTarget(t *testing.T) {
	useSettings(t)
	m := NewManager(20, t.TempDir())
	tok, _ := subToken()

	rec := httptest.NewRecorder()
	handleSocksSub(m)(rec, httptest.NewRequest(http.MethodGet, "/socks?token="+tok+"&target=xxx", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("不认识的 target 应当 400，实际 %d", rec.Code)
	}
}

// 名字重名时不能互相覆盖：Clash 按名字索引。
func TestSocksSubNamesUnique(t *testing.T) {
	entries := []socksSubEntry{
		{Name: "🇯🇵 日本 243", Port: 1001},
		{Name: "🇯🇵 日本 243", Port: 1002},
		{Name: "🇯🇵 日本 243", Port: 1002},
	}
	names := socksSubNames(entries)
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("名字重名了: %q", n)
		}
		seen[n] = true
	}
	if len(seen) != len(entries) {
		t.Fatalf("应当有 %d 个不同的名字，实际 %d", len(entries), len(seen))
	}
}

// 订阅必须能免登录访问，否则客户端根本拉不动。
func TestAuthLetsSocksThrough(t *testing.T) {
	dir := t.TempDir()
	a, _, err := NewAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	h := a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/socks?token=x", nil))
	if !reached {
		t.Fatal("/socks 应当放行给 handleSocksSub 自己验口令")
	}
}
