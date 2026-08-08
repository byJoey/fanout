package main

import (
	"net"
	"strconv"
	"strings"
)

func buildSingBoxGatewayConfig(inbounds []*nativeInbound, tunnels []*Tunnel) map[string]any {
	live := map[string]bool{}
	for _, t := range tunnels {
		if t.Status == "up" {
			live[sanitizeTag(t.Node.HostName)] = true
		}
	}

	ins := make([]any, 0, len(inbounds))
	for _, inbound := range inbounds {
		if inbound.Enable {
			ins = append(ins, singBoxInboundJSON(inbound))
		}
	}

	outs := []any{
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "block", "tag": "block"},
	}
	for _, t := range tunnels {
		if t.Status != "up" {
			continue
		}
		cred := t.credential()
		out := map[string]any{
			"type": "socks", "tag": tunnelTag(t),
			"server": "127.0.0.1", "server_port": t.Port,
		}
		if cred.User != "" {
			out["username"] = cred.User
			out["password"] = cred.Pass
		}
		outs = append(outs, out)
	}

	rules := make([]any, 0, len(inbounds))
	for _, inbound := range inbounds {
		if !inbound.Enable || inbound.BoundTo == "" || !live[inbound.BoundTo] {
			continue
		}
		rules = append(rules, map[string]any{
			"inbound": []string{inbound.tag()},
			"action":  "route", "outbound": tunnelTagPrefix + inbound.BoundTo,
		})
	}

	return map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  ins,
		"outbounds": outs,
		"route": map[string]any{
			"rules": rules,
			"final": "direct",
		},
	}
}

func singBoxInboundJSON(inbound *nativeInbound) map[string]any {
	users := make([]any, 0, len(inbound.Clients))
	for _, client := range inbound.Clients {
		if !client.Enable {
			continue
		}
		switch inbound.Protocol {
		case "trojan":
			users = append(users, map[string]any{"name": client.Email, "password": client.Password})
		case "vmess":
			users = append(users, map[string]any{"name": client.Email, "uuid": client.ID})
		default:
			user := map[string]any{"name": client.Email, "uuid": client.ID}
			if client.Flow != "" {
				user["flow"] = client.Flow
			}
			users = append(users, user)
		}
	}

	result := map[string]any{
		"type": inbound.Protocol, "tag": inbound.tag(),
		"listen": "0.0.0.0", "listen_port": inbound.Port,
		"users": users,
	}
	if transport := singBoxTransportJSON(inbound); transport != nil {
		result["transport"] = transport
	}
	if tlsOptions := singBoxInboundTLSJSON(inbound); tlsOptions != nil {
		result["tls"] = tlsOptions
	}
	return result
}

func singBoxTransportJSON(inbound *nativeInbound) map[string]any {
	path := inbound.Path
	if path == "" {
		path = "/"
	}
	switch inbound.netOrTCP() {
	case "ws":
		transport := map[string]any{"type": "ws", "path": path}
		if inbound.Host != "" {
			transport["headers"] = map[string]any{"Host": inbound.Host}
		}
		return transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade", "path": path}
		if inbound.Host != "" {
			transport["host"] = inbound.Host
		}
		return transport
	case "grpc":
		return map[string]any{
			"type": "grpc", "service_name": strings.TrimPrefix(inbound.Path, "/"),
		}
	default:
		return nil
	}
}

func singBoxInboundTLSJSON(inbound *nativeInbound) map[string]any {
	switch inbound.securityOrNone() {
	case "tls":
		if inbound.TLS == nil {
			return nil
		}
		options := map[string]any{
			"enabled":          true,
			"certificate_path": inbound.TLS.CertFile,
			"key_path":         inbound.TLS.KeyFile,
		}
		if inbound.TLS.ServerName != "" {
			options["server_name"] = inbound.TLS.ServerName
		}
		return options
	case "reality":
		if inbound.Reality == nil {
			return nil
		}
		host, portText, err := net.SplitHostPort(inbound.Reality.Dest)
		if err != nil {
			host = inbound.Reality.Dest
			portText = "443"
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			port = 443
		}
		options := map[string]any{
			"enabled": true,
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": host, "server_port": port},
				"private_key": inbound.Reality.PrivateKey,
				"short_id":    inbound.Reality.ShortIDs,
			},
		}
		if len(inbound.Reality.ServerNames) > 0 {
			options["server_name"] = inbound.Reality.ServerNames[0]
		}
		return options
	default:
		return nil
	}
}
