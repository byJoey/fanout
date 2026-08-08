package main

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestNormalizeListenAddr(t *testing.T) {
	cases := map[string]string{
		"":          "",
		"0.0.0.0":   "",
		"all":       "",
		"127.0.0.1": "127.0.0.1",
	}
	for in, want := range cases {
		got, err := normalizeListenAddr(in)
		if err != nil {
			t.Fatalf("normalizeListenAddr(%q) 意外报错: %v", in, err)
		}
		if got != want {
			t.Fatalf("normalizeListenAddr(%q)=%q，想要 %q", in, got, want)
		}
	}
	if _, err := normalizeListenAddr("not-an-ip"); err == nil {
		t.Fatal("非法监听地址应当报错")
	}
}

func TestValidatePort(t *testing.T) {
	for _, p := range []int{1, 8899, 65535} {
		if err := validatePort(p); err != nil {
			t.Fatalf("端口 %d 应合法: %v", p, err)
		}
	}
	for _, p := range []int{0, -1, 70000} {
		if err := validatePort(p); err == nil {
			t.Fatalf("端口 %d 应非法", p)
		}
	}
}

func TestInboundPortRangeDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadWebSettings(dir, 8899)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InboundPortMin != 50000 || cfg.InboundPortMax != 60000 {
		t.Fatalf("默认入站端口范围错误: %d-%d", cfg.InboundPortMin, cfg.InboundPortMax)
	}
	for _, pair := range [][2]int{{1, 1}, {50000, 60000}, {65535, 65535}} {
		if err := validatePortRange(pair[0], pair[1]); err != nil {
			t.Errorf("合法范围 %v 被拒绝: %v", pair, err)
		}
	}
	for _, pair := range [][2]int{{0, 1}, {60000, 50000}, {1, 65536}} {
		if err := validatePortRange(pair[0], pair[1]); err == nil {
			t.Errorf("非法范围 %v 未被拒绝", pair)
		}
	}
}

func TestSetBasePathValidatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	if _, err := initBasePath(dir); err != nil {
		t.Fatalf("initBasePath: %v", err)
	}
	bp, err := setBasePath("myPanel_1")
	if err != nil {
		t.Fatalf("setBasePath: %v", err)
	}
	if bp != "/myPanel_1" || currentBasePath() != "/myPanel_1" {
		t.Fatalf("basePath 未生效: %q / %q", bp, currentBasePath())
	}
	if _, err := os.ReadFile(dir + "/basepath"); err != nil {
		t.Fatalf("basepath 未落盘: %v", err)
	}
	if _, err := setBasePath("bad/slash"); err == nil {
		t.Fatal("带非法字符的路径应被拒")
	}
	// 空串表示去掉前缀
	if bp, err := setBasePath(""); err != nil || bp != "" {
		t.Fatalf("空路径应清空前缀: %q %v", bp, err)
	}
}

func TestAuthSetPassword(t *testing.T) {
	dir := t.TempDir()
	auth, _, err := NewAuth(dir)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	if err := auth.SetPassword("newsecret"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !auth.check("newsecret") {
		t.Fatal("新口令应校验通过")
	}
	if auth.check("wrong") {
		t.Fatal("旧口令不应再通过")
	}
	if err := auth.SetPassword(""); err == nil {
		t.Fatal("空口令应被拒")
	}
	if err := auth.SetPassword("ab"); err == nil {
		t.Fatal("过短口令应被拒")
	}
}

func TestWebServerReloadSwitchesPort(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadWebSettings(dir, 0); err != nil {
		t.Fatalf("loadWebSettings: %v", err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	srv := newWebServer(h)

	// 用两个系统分配的空闲端口验证切换
	p1 := freePort(t)
	if err := srv.reload(WebSettings{Port: p1, ListenAddr: "127.0.0.1"}); err != nil {
		t.Fatalf("reload p1: %v", err)
	}
	waitServe(t, p1)

	p2 := freePort(t)
	if err := srv.applyWebSettings(WebSettings{Port: p2, ListenAddr: "127.0.0.1"}); err != nil {
		t.Fatalf("applyWebSettings p2: %v", err)
	}
	waitServe(t, p2)

	// 旧端口应在优雅关闭后不再接受连接
	time.Sleep(1500 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p1)), 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatalf("旧端口 %d 切换后仍在监听", p1)
	}

	// 非法端口应被拒，且不影响现有监听
	if err := srv.applyWebSettings(WebSettings{Port: 70000, ListenAddr: "127.0.0.1"}); err == nil {
		t.Fatal("非法端口应被拒")
	}
	waitServe(t, p2)
}

func waitServe(t *testing.T, port int) {
	t.Helper()
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"
	for i := 0; i < 40; i++ {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("端口 %d 未在预期时间内提供服务", port)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
