package main

import (
	"fmt"
	"strings"
)

// normalizedSpec 是 NewInboundSpec 过完校验、补完默认值之后的样子。
// The normalized form is persisted as a nativeInbound and rendered as sing-box JSON.
type normalizedSpec struct {
	Protocol string
	Network  string
	Security string
	Port     int
	Path     string
	Host     string
	Remark   string
	Flow     string
}

// normalizeInboundSpec 校验协议组合并补上默认值。
//
// used 是已被占用的端口集合；端口留空时从中避开随机挑一个。
// Keeping validation separate from persistence also makes protocol combinations testable.
func normalizeInboundSpec(spec NewInboundSpec, used map[int]bool) (*normalizedSpec, error) {
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if proto == "" {
		proto = "vless"
	}
	if !nativeProtocols[proto] {
		return nil, fmt.Errorf("不支持的协议 %q", spec.Protocol)
	}
	network := strings.ToLower(strings.TrimSpace(spec.Network))
	if network == "" {
		network = "tcp"
	}
	if !nativeNetworks[network] {
		return nil, fmt.Errorf("不支持的传输方式 %q", spec.Network)
	}
	security := strings.ToLower(strings.TrimSpace(spec.Security))
	if security == "" {
		security = "none"
	}
	if !nativeSecurities[security] {
		return nil, fmt.Errorf("不支持的安全层 %q", spec.Security)
	}
	// REALITY cannot wrap WebSocket or HTTPUpgrade.
	if security == "reality" && network != "tcp" && network != "grpc" {
		return nil, fmt.Errorf("REALITY 不支持 %s 传输", network)
	}
	// VMess 自带加密，但 TLS 在这里是为了流量伪装而不是加密强度，
	// vmess+ws+tls 是很常见的组合，不该拦。

	port := spec.Port
	if port == 0 {
		p, err := freeRandomPort(used)
		if err != nil {
			return nil, err
		}
		port = p
	} else if used[port] {
		return nil, fmt.Errorf("端口 %d 已被别的入站占用", port)
	}

	path := strings.TrimSpace(spec.Path)
	if path == "" {
		switch network {
		case "ws", "httpupgrade":
			path = "/" + randomHex(6)
		case "grpc":
			path = randomHex(6)
		}
	}

	remark := strings.TrimSpace(spec.Remark)
	if remark == "" {
		remark = fmt.Sprintf("%s-%d", proto, port)
	}

	flow := ""
	if spec.Vision {
		if !visionCapable(proto, network, security) {
			return nil, fmt.Errorf("xtls-rprx-vision 只能用于 VLESS + TCP + TLS/REALITY")
		}
		flow = "xtls-rprx-vision"
	}

	return &normalizedSpec{
		Protocol: proto,
		Network:  network,
		Security: security,
		Port:     port,
		Path:     path,
		Host:     strings.TrimSpace(spec.Host),
		Remark:   remark,
		Flow:     flow,
	}, nil
}
