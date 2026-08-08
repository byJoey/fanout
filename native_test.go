package main

import (
	"strings"
	"testing"
)

func TestNativeInboundTagStable(t *testing.T) {
	cases := []struct {
		ib   nativeInbound
		want string
	}{
		{nativeInbound{Port: 443, Network: "tcp"}, "in-443-tcp"},
		{nativeInbound{Port: 8080, Network: "ws"}, "in-8080-ws"},
		{nativeInbound{Port: 1234}, "in-1234-tcp"}, // 缺省按 tcp
	}
	for _, c := range cases {
		if got := c.ib.tag(); got != c.want {
			t.Errorf("tag() = %q, want %q", got, c.want)
		}
	}
}

func TestBuildSingBoxConfigBindsOnlyLiveTunnels(t *testing.T) {
	up := &Tunnel{Port: 1080, Status: "up", Node: Node{HostName: "jp1"}}
	down := &Tunnel{Port: 1081, Status: "failed", Node: Node{HostName: "jp2"}}
	inbounds := []*nativeInbound{
		{ID: 1, Port: 100, Protocol: "vless", Enable: true, BoundTo: "jp1"},
		{ID: 2, Port: 200, Protocol: "vless", Enable: true, BoundTo: "jp2"},
		{ID: 3, Port: 300, Protocol: "vless", Enable: true},
	}

	cfg := buildSingBoxGatewayConfig(inbounds, []*Tunnel{up, down})

	outs := map[string]bool{}
	for _, o := range cfg["outbounds"].([]any) {
		outs[o.(map[string]any)["tag"].(string)] = true
	}
	if !outs["fanout-jp1"] {
		t.Error("已连通的隧道应当有对应出站")
	}
	if outs["fanout-jp2"] {
		t.Error("未连通的隧道不该生成出站")
	}

	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("只有绑到连通隧道的入站才该有规则，实际 %d 条", len(rules))
	}
	if got := rules[0].(map[string]any)["outbound"]; got != "fanout-jp1" {
		t.Errorf("outbound = %v, want fanout-jp1", got)
	}
}

func TestBuildSingBoxConfigHasDirectFallback(t *testing.T) {
	cfg := buildSingBoxGatewayConfig(nil, nil)
	for _, o := range cfg["outbounds"].([]any) {
		m := o.(map[string]any)
		if m["tag"] != "direct" {
			continue
		}
		if m["type"] != "direct" {
			t.Errorf("direct 出站类型错误: %v", m["type"])
		}
		if cfg["route"].(map[string]any)["final"] != "direct" {
			t.Error("未绑定入站应走 direct")
		}
		return
	}
	t.Fatal("没有找到 direct 出站")
}

func TestShareLinkPerProtocol(t *testing.T) {
	c := nativeClient{ID: "uuid-1", Password: "pw-1", Email: "e", Enable: true}

	vless := shareLink(&nativeInbound{Port: 100, Protocol: "vless", Remark: "r"}, c, "1.2.3.4")
	if !strings.HasPrefix(vless, "vless://uuid-1@1.2.3.4:100?") {
		t.Errorf("vless 链接格式不对: %s", vless)
	}
	if !strings.Contains(vless, "encryption=none") {
		t.Errorf("vless 需要 encryption=none: %s", vless)
	}

	tro := shareLink(&nativeInbound{Port: 200, Protocol: "trojan", Network: "ws", Path: "/p"}, c, "h")
	if !strings.HasPrefix(tro, "trojan://pw-1@h:200?") {
		t.Errorf("trojan 应当用密码而不是 UUID: %s", tro)
	}
	if !strings.Contains(tro, "path=%2Fp") {
		t.Errorf("ws 链接要带 path: %s", tro)
	}
}

func TestCloneRemark(t *testing.T) {
	if got := cloneRemark("线路A", "JP-244"); got != "线路A-JP-244" {
		t.Errorf("cloneRemark = %q", got)
	}
	if got := cloneRemark("", "JP-244"); got != "JP-244" {
		t.Errorf("空备注时应直接用标签，实际 %q", got)
	}
}

func TestVisionCapable(t *testing.T) {
	// Vision is valid only for VLESS + TCP + TLS/REALITY.
	if !visionCapable("vless", "tcp", "reality") {
		t.Error("vless/tcp/reality 应当支持 vision")
	}
	if !visionCapable("vless", "tcp", "tls") {
		t.Error("vless/tcp/tls 应当支持 vision")
	}
	if visionCapable("vless", "ws", "tls") {
		t.Error("ws 不该支持 vision")
	}
	if visionCapable("vless", "tcp", "none") {
		t.Error("没有安全层时不该支持 vision")
	}
	if visionCapable("trojan", "tcp", "tls") {
		t.Error("vision 是 VLESS 专属")
	}
}

func TestSingBoxTransportPerNetwork(t *testing.T) {
	cases := []struct {
		ib      nativeInbound
		wantKey string
		want    any
	}{
		{nativeInbound{Network: "ws", Path: "/p"}, "path", "/p"},
		{nativeInbound{Network: "httpupgrade", Path: "/h"}, "path", "/h"},
		// gRPC 没有 path，Path 字段复用为 serviceName，且不带前导斜杠
		{nativeInbound{Network: "grpc", Path: "/svc"}, "service_name", "svc"},
	}
	for _, c := range cases {
		transport := singBoxTransportJSON(&c.ib)
		if transport == nil {
			t.Errorf("%s 缺少 transport", c.ib.Network)
			continue
		}
		if got := transport[c.wantKey]; got != c.want {
			t.Errorf("%s 的 %s = %v, want %v", c.ib.Network, c.wantKey, got, c.want)
		}
	}
}

func TestSingBoxInboundReality(t *testing.T) {
	ib := nativeInbound{
		Network: "tcp", Security: "reality",
		Reality: &realityConfig{
			Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
			PrivateKey: "priv", PublicKey: "pub", ShortIDs: []string{"abcd1234"},
		},
	}
	tlsOptions := singBoxInboundTLSJSON(&ib)
	r, ok := tlsOptions["reality"].(map[string]any)
	if !ok {
		t.Fatal("缺少 reality")
	}
	if r["private_key"] != "priv" {
		t.Errorf("服务端要写私钥，实际 %v", r["private_key"])
	}
	if _, leaked := r["public_key"]; leaked {
		t.Error("服务端配置不该出现 publicKey")
	}
}

func TestShareLinkCarriesSecurityParams(t *testing.T) {
	c := nativeClient{ID: "uuid-1", Enable: true, Flow: "xtls-rprx-vision"}

	re := shareLink(&nativeInbound{
		Port: 100, Protocol: "vless", Network: "tcp", Security: "reality", Remark: "r",
		Reality: &realityConfig{
			ServerNames: []string{"www.cloudflare.com"}, PublicKey: "PBK",
			ShortIDs: []string{"sid1"}, Fingerprint: "chrome",
		},
	}, c, "h")
	for _, want := range []string{"pbk=PBK", "sid=sid1", "fp=chrome",
		"sni=www.cloudflare.com", "flow=xtls-rprx-vision"} {
		if !strings.Contains(re, want) {
			t.Errorf("REALITY 链接缺少 %s: %s", want, re)
		}
	}

	// 自签证书验不过 CA，链接必须带指纹，否则客户端连不上
	tl := shareLink(&nativeInbound{
		Port: 200, Protocol: "vless", Network: "tcp", Security: "tls", Remark: "t",
		TLS: &tlsConfig{ServerName: "demo.local", SelfSigned: true, CertSha256: "AABB"},
	}, nativeClient{ID: "u", Enable: true}, "h")
	if !strings.Contains(tl, "pinSHA256=AABB") {
		t.Errorf("自签 TLS 链接要带证书指纹: %s", tl)
	}
}
