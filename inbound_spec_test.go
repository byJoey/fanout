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
