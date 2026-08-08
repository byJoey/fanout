package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type openVPNProfile struct {
	directives map[string][][]string
	inline     map[string]string
}

func parseOpenVPNProfile(text string) (*openVPNProfile, error) {
	p := &openVPNProfile{
		directives: make(map[string][][]string),
		inline:     make(map[string]string),
	}
	s := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(text, "\r\n", "\n")))
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">"))
			var body strings.Builder
			closed := false
			for s.Scan() {
				if strings.EqualFold(strings.TrimSpace(s.Text()), "</"+name+">") {
					closed = true
					break
				}
				body.WriteString(s.Text())
				body.WriteByte('\n')
			}
			if !closed {
				return nil, fmt.Errorf("OpenVPN 配置中的 <%s> 没有结束标签", name)
			}
			p.inline[name] = strings.TrimSpace(body.String()) + "\n"
			continue
		}
		fields, err := splitOpenVPNLine(line)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimLeft(fields[0], "-"))
		p.directives[name] = append(p.directives[name], fields[1:])
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("读取 OpenVPN 配置失败: %w", err)
	}
	return p, nil
}

// splitOpenVPNLine handles the quoting and escaping used by OpenVPN profiles.
// Comments are recognized only outside quotes, matching OpenVPN's config lexer.
func splitOpenVPNLine(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' || r == ';' {
			break
		}
		if unicode.IsSpace(r) {
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	if escaped {
		return nil, fmt.Errorf("OpenVPN 配置行以转义符结尾: %q", line)
	}
	if quote != 0 {
		return nil, fmt.Errorf("OpenVPN 配置行引号未闭合: %q", line)
	}
	flush()
	return out, nil
}

func (p *openVPNProfile) first(name string) []string {
	values := p.directives[name]
	if len(values) == 0 {
		return nil
	}
	return values[0]
}

func (p *openVPNProfile) has(name string) bool {
	_, ok := p.directives[name]
	return ok
}

func normalizeOpenVPNNetwork(value string) (string, error) {
	v := strings.ToLower(value)
	switch {
	case strings.HasPrefix(v, "tcp"):
		return "tcp", nil
	case strings.HasPrefix(v, "udp") || v == "":
		return "udp", nil
	default:
		return "", fmt.Errorf("不支持的 OpenVPN proto %q", value)
	}
}

func openVPNDirection(value string) string {
	switch strings.ToLower(value) {
	case "0", "server":
		return "server"
	case "1", "client":
		return "client"
	default:
		return ""
	}
}

func splitColonList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ":") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseOpenVPNUint(args []string) uint64 {
	if len(args) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(args[0], 10, 32)
	return n
}

// openVPNEndpoint converts the subset used by VPN Gate profiles into a
// sing-box 1.14 OpenVPN client endpoint. Unknown directives are deliberately
// ignored; they are mostly process/OS options such as nobind and persist-tun.
func openVPNEndpoint(profile, tag string) (map[string]any, error) {
	p, err := parseOpenVPNProfile(profile)
	if err != nil {
		return nil, err
	}
	remotes := p.directives["remote"]
	if len(remotes) == 0 || len(remotes[0]) < 2 {
		return nil, fmt.Errorf("OpenVPN 配置缺少 remote 主机和端口")
	}
	defaultNetwork := "udp"
	if args := p.first("proto"); len(args) > 0 {
		defaultNetwork, err = normalizeOpenVPNNetwork(args[0])
		if err != nil {
			return nil, err
		}
	}

	endpoint := map[string]any{
		"type":       "openvpn-client",
		"tag":        tag,
		"system":     false,
		"network":    defaultNetwork,
		"username":   "vpn",
		"password":   "vpn",
		"block_ipv6": true,
	}
	if len(remotes) == 1 {
		port, err := strconv.Atoi(remotes[0][1])
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("OpenVPN remote 端口无效: %q", remotes[0][1])
		}
		endpoint["server"] = remotes[0][0]
		endpoint["server_port"] = port
		if len(remotes[0]) > 2 {
			network, err := normalizeOpenVPNNetwork(remotes[0][2])
			if err != nil {
				return nil, err
			}
			endpoint["network"] = network
		}
	} else {
		servers := make([]any, 0, len(remotes))
		for _, remote := range remotes {
			if len(remote) < 2 {
				continue
			}
			port, err := strconv.Atoi(remote[1])
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("OpenVPN remote 端口无效: %q", remote[1])
			}
			server := map[string]any{"server": remote[0], "server_port": port}
			if len(remote) > 2 {
				network, err := normalizeOpenVPNNetwork(remote[2])
				if err != nil {
					return nil, err
				}
				server["network"] = network
			}
			servers = append(servers, server)
		}
		endpoint["servers"] = servers
	}

	tlsOptions := map[string]any{}
	if value := p.inline["ca"]; value != "" {
		tlsOptions["certificate"] = []string{value}
	}
	if value := p.inline["cert"]; value != "" {
		tlsOptions["client_certificate"] = []string{value}
	}
	if value := p.inline["key"]; value != "" {
		tlsOptions["client_key"] = []string{value}
	}
	if args := p.first("remote-cert-tls"); len(args) > 0 {
		tlsOptions["remote_certificate_tls"] = args[0]
	}
	if args := p.first("tls-version-min"); len(args) > 0 {
		tlsOptions["version_min"] = args[0]
	}
	if args := p.first("tls-version-max"); len(args) > 0 {
		tlsOptions["version_max"] = args[0]
	}
	if args := p.first("tls-cipher"); len(args) > 0 {
		tlsOptions["cipher"] = strings.Join(args, ":")
	}

	for _, item := range []struct {
		block string
		type_ string
	}{
		{"tls-auth", "tls_auth"},
		{"tls-crypt", "tls_crypt"},
		{"tls-crypt-v2", "tls_crypt_v2"},
	} {
		if key := p.inline[item.block]; key != "" {
			wrap := map[string]any{"type": item.type_, "key": []string{key}}
			direction := ""
			if args := p.first("key-direction"); len(args) > 0 {
				direction = openVPNDirection(args[0])
			}
			if args := p.first(item.block); direction == "" && len(args) > 1 {
				direction = openVPNDirection(args[1])
			}
			if direction != "" && item.type_ == "tls_auth" {
				wrap["direction"] = direction
			}
			tlsOptions["control_wrap"] = wrap
			break
		}
	}
	if len(tlsOptions) == 0 {
		return nil, fmt.Errorf("OpenVPN 配置缺少 TLS/CA 信息")
	}
	endpoint["tls"] = tlsOptions

	if args := p.first("cipher"); len(args) > 0 {
		endpoint["data_ciphers_fallback"] = args[0]
	}
	if args := p.first("data-ciphers"); len(args) > 0 {
		endpoint["data_ciphers"] = splitColonList(args[0])
	}
	if args := p.first("auth"); len(args) > 0 {
		endpoint["auth"] = args[0]
	}
	if args := p.first("mssfix"); len(args) > 0 {
		endpoint["mss_fix"] = parseOpenVPNUint(args)
	}
	if args := p.first("fragment"); len(args) > 0 {
		endpoint["fragment"] = parseOpenVPNUint(args)
	}
	if args := p.first("compress"); len(args) > 0 {
		endpoint["compression"] = args[0]
	}
	if args := p.first("comp-lzo"); len(args) > 0 {
		endpoint["compression_lzo"] = args[0]
	} else if p.has("comp-lzo") {
		endpoint["compression_lzo"] = "adaptive"
	}
	if p.has("route-nopull") || p.has("route-no-pull") {
		endpoint["route_no_pull"] = true
	}
	if args := p.first("redirect-gateway"); args != nil {
		endpoint["redirect_gateway"] = true
		if len(args) > 0 {
			endpoint["redirect_gateway_flags"] = args
		}
	}
	if args := p.first("ping"); len(args) > 0 {
		endpoint["ping_interval"] = args[0] + "s"
	}
	if args := p.first("ping-restart"); len(args) > 0 {
		endpoint["ping_restart"] = args[0] + "s"
	}
	if args := p.first("reneg-sec"); len(args) > 0 {
		endpoint["renegotiate_interval"] = args[0] + "s"
	}
	return endpoint, nil
}

func buildTunnelSingBoxConfig(profile string, port int) (map[string]any, error) {
	endpoint, err := openVPNEndpoint(profile, "vpn")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"endpoints": []any{endpoint},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "internal-socks",
			"listen": "127.0.0.1", "listen_port": port,
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route": map[string]any{
			"rules": []any{map[string]any{
				"inbound": []string{"internal-socks"},
				"action":  "route", "outbound": "vpn",
			}},
			"final": "direct",
		},
	}, nil
}
