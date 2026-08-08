package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const testVPNGateProfile = `
dev tun
proto tcp
remote 198.51.100.10 443
cipher AES-128-CBC
data-ciphers AES-128-CBC:AES-256-GCM
auth SHA1
client
<ca>
-----BEGIN CERTIFICATE-----
TEST-CA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
TEST-CLIENT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
TEST-KEY
-----END PRIVATE KEY-----
</key>
`

func TestOpenVPNEndpointConvertsVPNGateProfile(t *testing.T) {
	endpoint, err := openVPNEndpoint(testVPNGateProfile, "vpn")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint["type"] != "openvpn-client" || endpoint["system"] != false {
		t.Fatalf("endpoint 基本字段错误: %+v", endpoint)
	}
	if endpoint["server"] != "198.51.100.10" || endpoint["server_port"] != 443 {
		t.Fatalf("remote 转换错误: %+v", endpoint)
	}
	if endpoint["network"] != "tcp" || endpoint["auth"] != "SHA1" {
		t.Fatalf("协议或认证算法错误: %+v", endpoint)
	}
	ciphers := endpoint["data_ciphers"].([]string)
	if len(ciphers) != 2 || ciphers[0] != "AES-128-CBC" {
		t.Fatalf("data-ciphers 转换错误: %+v", ciphers)
	}
	tlsOptions := endpoint["tls"].(map[string]any)
	if len(tlsOptions["certificate"].([]string)) != 1 || len(tlsOptions["client_key"].([]string)) != 1 {
		t.Fatalf("内联证书转换错误: %+v", tlsOptions)
	}
}

func TestOpenVPNEndpointTLSAuthDirection(t *testing.T) {
	profile := `
proto udp
remote vpn.example 1194
key-direction 1
<ca>
CA
</ca>
<tls-auth>
STATIC-KEY
</tls-auth>
`
	endpoint, err := openVPNEndpoint(profile, "vpn")
	if err != nil {
		t.Fatal(err)
	}
	tlsOptions := endpoint["tls"].(map[string]any)
	wrap := tlsOptions["control_wrap"].(map[string]any)
	if wrap["type"] != "tls_auth" || wrap["direction"] != "client" {
		t.Fatalf("tls-auth 转换错误: %+v", wrap)
	}
}

func TestOpenVPNEndpointRejectsMissingRemote(t *testing.T) {
	if _, err := openVPNEndpoint("client\n<ca>\nCA\n</ca>\n", "vpn"); err == nil {
		t.Fatal("缺少 remote 应报错")
	}
}

func TestSplitOpenVPNLine(t *testing.T) {
	got, err := splitOpenVPNLine(`remote "vpn host" 443 # comment`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1] != "vpn host" || got[2] != "443" {
		t.Fatalf("解析结果错误: %#v", got)
	}
}

func TestTunnelConfigRoutesInternalSocksToVPN(t *testing.T) {
	cfg, err := buildTunnelSingBoxConfig(testVPNGateProfile, 12345)
	if err != nil {
		t.Fatal(err)
	}
	inbound := cfg["inbounds"].([]any)[0].(map[string]any)
	if inbound["listen"] != "127.0.0.1" || inbound["listen_port"] != 12345 {
		t.Fatalf("内部 SOCKS 监听错误: %+v", inbound)
	}
	rule := cfg["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["outbound"] != "vpn" {
		t.Fatalf("路由未指向 OpenVPN endpoint: %+v", rule)
	}
}

func TestTunnelConfigPassesSingBoxCheck(t *testing.T) {
	bin := os.Getenv("FANOUT_SINGBOX_BIN")
	if bin == "" {
		t.Skip("FANOUT_SINGBOX_BIN 未设置")
	}
	cfg, err := buildTunnelSingBoxConfig(testVPNGateProfile, 12345)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel.json")
	blob, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check 失败: %v\n%s", err, out)
	}
}

func TestGatewayConfigPassesSingBoxCheck(t *testing.T) {
	bin := os.Getenv("FANOUT_SINGBOX_BIN")
	if bin == "" {
		t.Skip("FANOUT_SINGBOX_BIN 未设置")
	}
	cfg := buildSingBoxGatewayConfig([]*nativeInbound{{
		ID: 1, Port: 24443, Protocol: "vless", Enable: true,
		Clients: []nativeClient{{Email: "test", ID: "7f5d6c7e-0e3a-4b48-83de-4ffcc1c7541c", Enable: true}},
		BoundTo: "jp1",
	}}, []*Tunnel{{
		Port: 18080, Status: "up", Node: Node{HostName: "jp1"},
		Cred: SocksCred{User: "test", Pass: "password"},
	}})
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	blob, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check 失败: %v\n%s", err, out)
	}
}

func TestGatewayAdvancedInboundsPassSingBoxCheck(t *testing.T) {
	bin := os.Getenv("FANOUT_SINGBOX_BIN")
	if bin == "" {
		t.Skip("FANOUT_SINGBOX_BIN 未设置")
	}
	dir := t.TempDir()
	cert, key, err := selfSignedCert(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey, err := realityKeys(bin)
	if err != nil {
		t.Fatal(err)
	}
	client := nativeClient{Email: "test", ID: "7f5d6c7e-0e3a-4b48-83de-4ffcc1c7541c", Password: "test-password", Enable: true}
	cfg := buildSingBoxGatewayConfig([]*nativeInbound{
		{ID: 1, Port: 24001, Protocol: "vless", Network: "tcp", Security: "reality", Enable: true, Clients: []nativeClient{client}, Reality: &realityConfig{
			Dest: "example.com:443", ServerNames: []string{"example.com"}, PrivateKey: privateKey, PublicKey: publicKey, ShortIDs: []string{"a1b2c3d4"},
		}},
		{ID: 2, Port: 24002, Protocol: "vless", Network: "ws", Path: "/ws", Host: "example.com", Security: "tls", Enable: true, Clients: []nativeClient{client}, TLS: &tlsConfig{
			ServerName: "example.com", CertFile: cert, KeyFile: key,
		}},
		{ID: 3, Port: 24003, Protocol: "vmess", Network: "grpc", Path: "service", Enable: true, Clients: []nativeClient{client}},
		{ID: 4, Port: 24004, Protocol: "trojan", Network: "httpupgrade", Path: "/up", Host: "example.com", Security: "tls", Enable: true, Clients: []nativeClient{client}, TLS: &tlsConfig{
			ServerName: "example.com", CertFile: cert, KeyFile: key,
		}},
	}, nil)
	path := filepath.Join(dir, "advanced.json")
	blob, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check 失败: %v\n%s", err, out)
	}
}
