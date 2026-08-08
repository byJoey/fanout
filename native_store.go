package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// nativeClient 是一个可连接的客户端凭据。
// 复制入站时同一个 client 会挂到所有出口上，用户换出口只需要改端口。
type nativeClient struct {
	Email    string `json:"email"`
	ID       string `json:"id"`       // vless/vmess 用 UUID
	Password string `json:"password"` // trojan 用密码
	Enable   bool   `json:"enable"`
	// Flow 只对 VLESS 有意义，取值 "" 或 xtls-rprx-vision。
	// Vision 要求底层是 TCP + TLS/REALITY。
	Flow string `json:"flow,omitempty"`
}

// nativeInbound 是自建模式下的一个入站。
//
// Fields mirror the UI's inbound model.
type nativeInbound struct {
	ID       int    `json:"id"`
	Port     int    `json:"port"`
	Listen   string `json:"listen,omitempty"` // runtime override; empty means IPv4 wildcard
	Protocol string `json:"protocol"`         // vless | vmess | trojan
	Network  string `json:"network"`          // tcp | ws | grpc | httpupgrade | udp (hysteria2)
	Path     string `json:"path"`             // ws/httpupgrade 路径，grpc 用作 serviceName
	Host     string `json:"host"`             // ws/httpupgrade 的 Host 头
	// Security 是传输层安全：none | tls | reality
	Security string         `json:"security"`
	TLS      *tlsConfig     `json:"tls,omitempty"`
	Reality  *realityConfig `json:"reality,omitempty"`
	Remark   string         `json:"remark"`
	Enable   bool           `json:"enable"`
	Clients  []nativeClient `json:"clients"`
	// BoundTo 是绑定的节点主机名经 sanitizeTag 后的形式，空表示直连
	BoundTo string `json:"bound_to"`
}

// tlsConfig 是标准 TLS 的配置。证书要么由用户提供路径，要么 fanout 生成自签的。
type tlsConfig struct {
	ServerName string `json:"server_name"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	// SelfSigned 记录证书是 fanout 生成的，分享链接要带 allowInsecure
	SelfSigned bool `json:"self_signed"`
	// CertSha256 是证书的 SHA-256 指纹（十六进制）。
	// 自签证书通过分享链接里的指纹建立信任。
	CertSha256 string `json:"cert_sha256,omitempty"`
}

// realityConfig 是 REALITY 的配置。
//
// PublicKey 服务端用不到，但客户端必须填，所以一并存下来供生成分享链接。
type realityConfig struct {
	Dest        string   `json:"dest"` // 借用的真实站点，如 www.microsoft.com:443
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	PublicKey   string   `json:"public_key"`
	ShortIDs    []string `json:"short_ids"`
	Fingerprint string   `json:"fingerprint"` // 客户端指纹，如 chrome
}

// tag identifies this inbound in sing-box routing rules.
func (n *nativeInbound) tag() string {
	return fmt.Sprintf("in-%d-%s", n.Port, n.netOrTCP())
}

func (n *nativeInbound) netOrTCP() string {
	if n.Network == "" {
		return "tcp"
	}
	return n.Network
}

func (n *nativeInbound) listenOrIPv4() string {
	if strings.TrimSpace(n.Listen) == "" {
		return "0.0.0.0"
	}
	return n.Listen
}

func (n *nativeInbound) securityOrNone() string {
	if n.Security == "" {
		return "none"
	}
	return n.Security
}

// nativeStore 是自建模式的持久状态。
type nativeStore struct {
	NextID   int              `json:"next_id"`
	Inbounds []*nativeInbound `json:"inbounds"`
}

func nativeStatePath(dir string) string { return filepath.Join(dir, "native.json") }

func loadNativeStore(dir string) (*nativeStore, error) {
	blob, err := os.ReadFile(nativeStatePath(dir))
	if os.IsNotExist(err) {
		return &nativeStore{NextID: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var st nativeStore
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", nativeStatePath(dir), err)
	}
	if st.NextID < 1 {
		st.NextID = 1
	}
	return &st, nil
}

func (s *nativeStore) save(dir string) error {
	blob, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := nativeStatePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, nativeStatePath(dir))
}

func (s *nativeStore) byID(id int) *nativeInbound {
	for _, ib := range s.Inbounds {
		if ib.ID == id {
			return ib
		}
	}
	return nil
}

func (s *nativeStore) usedPorts(network ...string) map[int]bool {
	used := map[int]bool{}
	for _, ib := range s.Inbounds {
		if len(network) > 0 && network[0] != "" && ib.netOrTCP() != network[0] {
			continue
		}
		used[ib.Port] = true
	}
	return used
}

// sorted 返回按端口排序的入站，让界面顺序稳定。
func (s *nativeStore) sorted() []*nativeInbound {
	out := make([]*nativeInbound, len(s.Inbounds))
	copy(out, s.Inbounds)
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// newUUID creates a UUID v4 accepted by VLESS and VMess.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 随机源不可用时退回一个仍然唯一的形式，避免建站直接失败
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

// randomHex 生成 n 字节的随机十六进制串，用作 trojan 密码与 ws 路径。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprint(os.Getpid())))
	}
	return hex.EncodeToString(b)
}
