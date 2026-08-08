package main

import "testing"

func TestNormalizeInboundSpecDefaults(t *testing.T) {
	ns, err := normalizeInboundSpec(NewInboundSpec{Port: 12345}, map[int]bool{})
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	if ns.Protocol != "vless" || ns.Network != "tcp" || ns.Security != "none" {
		t.Fatalf("默认值不对: %+v", ns)
	}
	if ns.Remark != "vless-12345" {
		t.Errorf("备注 = %q, want vless-12345", ns.Remark)
	}
	if ns.Path != "" {
		t.Errorf("tcp 不该生成路径, got %q", ns.Path)
	}
}

func TestNormalizeInboundSpecGeneratesPath(t *testing.T) {
	for _, net := range []string{"ws", "httpupgrade", "grpc"} {
		ns, err := normalizeInboundSpec(NewInboundSpec{Network: net, Port: 1234}, map[int]bool{})
		if err != nil {
			t.Fatalf("%s: %v", net, err)
		}
		if ns.Path == "" {
			t.Errorf("%s 应自动生成路径", net)
		}
	}
}

func TestNormalizeHysteria2DefaultsToUDPAndTLS(t *testing.T) {
	ns, err := normalizeInboundSpec(NewInboundSpec{Protocol: "hysteria2", Port: 1234}, nil)
	if err != nil {
		t.Fatalf("Hysteria2 默认值不应报错: %v", err)
	}
	if ns.Network != "udp" || ns.Security != "tls" {
		t.Fatalf("Hysteria2 默认值错误: %+v", ns)
	}
}

func TestNormalizeTUICDefaultsToUDPAndTLS(t *testing.T) {
	ns, err := normalizeInboundSpec(NewInboundSpec{Protocol: "tuic", Port: 1235}, nil)
	if err != nil {
		t.Fatalf("TUIC 默认值不应报错: %v", err)
	}
	if ns.Network != "udp" || ns.Security != "tls" {
		t.Fatalf("TUIC 默认值错误: %+v", ns)
	}
}

func TestValidateInboundListenAddr(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::", "127.0.0.1", "2001:db8::1"} {
		if err := validateInboundListenAddr(addr); err != nil {
			t.Errorf("监听地址 %q 应合法: %v", addr, err)
		}
	}
	if err := validateInboundListenAddr("not-an-ip"); err == nil {
		t.Fatal("非法监听地址应被拒绝")
	}
}

func TestNormalizeInboundSpecRejects(t *testing.T) {
	cases := []struct {
		name string
		spec NewInboundSpec
		used map[int]bool
	}{
		{"未知协议", NewInboundSpec{Protocol: "ss", Port: 1}, nil},
		{"未知传输", NewInboundSpec{Network: "quic", Port: 1}, nil},
		{"XHTTP 不兼容", NewInboundSpec{Network: "xhttp", Port: 1}, nil},
		{"未知安全层", NewInboundSpec{Security: "xtls", Port: 1}, nil},
		{"REALITY 配 ws", NewInboundSpec{Network: "ws", Security: "reality", Port: 1}, nil},
		{"端口占用", NewInboundSpec{Port: 443}, map[int]bool{443: true}},
		{"vision 配 ws", NewInboundSpec{Network: "ws", Security: "tls", Vision: true, Port: 1}, nil},
		{"VLESS 不可直接声明 UDP 传输", NewInboundSpec{Protocol: "vless", Network: "udp", Port: 1}, nil},
		{"Hysteria2 不可用明文", NewInboundSpec{Protocol: "hysteria2", Network: "udp", Security: "none", Port: 1}, nil},
	}
	for _, c := range cases {
		if _, err := normalizeInboundSpec(c.spec, c.used); err == nil {
			t.Errorf("%s: 应当报错但通过了", c.name)
		}
	}
}

func TestNormalizeInboundSpecVision(t *testing.T) {
	ns, err := normalizeInboundSpec(NewInboundSpec{
		Protocol: "vless", Network: "tcp", Security: "reality", Vision: true, Port: 1234,
	}, nil)
	if err != nil {
		t.Fatalf("意外报错: %v", err)
	}
	if ns.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q, want xtls-rprx-vision", ns.Flow)
	}
}
