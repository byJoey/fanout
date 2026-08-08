package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// checkRealityDest 确认 dest 能完成 TLS1.3 握手。
//
// REALITY 会把每个连接都转给 dest 做一次真实握手，dest 握手走不完时
// 服务端只会静默回落，客户端看到的是 EOF，很难查。宁可建站时就报错。
func checkRealityDest(dest, serverName string) error {
	conn, err := net.DialTimeout("tcp", dest, 8*time.Second)
	if err != nil {
		return fmt.Errorf("连不上 %s: %w", dest, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	c := tls.Client(conn, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	})
	if err := c.Handshake(); err != nil {
		return fmt.Errorf("%s 的 TLS1.3 握手失败: %w", dest, err)
	}
	return nil
}

// realityKeys asks sing-box to generate the key pair in its native format.
func realityKeys(bin string) (priv, pub string, err error) {
	out, err := exec.Command(bin, "generate", "reality-keypair").Output()
	if err != nil {
		return "", "", fmt.Errorf("生成 REALITY 密钥失败: %w", err)
	}
	text := string(out)

	rePriv := regexp.MustCompile(`(?i)private\s*key:\s*(\S+)`)
	rePub := regexp.MustCompile(`(?i)public\s*key:\s*(\S+)`)

	mp := rePriv.FindStringSubmatch(text)
	mb := rePub.FindStringSubmatch(text)
	if mp == nil || mb == nil {
		return "", "", fmt.Errorf("无法解析 sing-box REALITY 密钥输出: %s", strings.TrimSpace(text))
	}
	return mp[1], mb[1], nil
}

// randomShortID 生成 REALITY 的 shortId。
// 长度必须是偶数且不超过 16 个十六进制字符。
func randomShortID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "0123abcd"
	}
	return hex.EncodeToString(b)
}

// selfSignedCert creates the certificate with Go's standard library so the
// installed service does not need the openssl command.
func selfSignedCert(dir, serverName string) (certFile, keyFile string, err error) {
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", err
	}
	base := filepath.Join(certDir, sanitizeTag(serverName))
	certFile, keyFile = base+".crt", base+".key"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("生成 TLS 私钥失败: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("生成证书序列号失败: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("生成自签证书失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// certFingerprint 算出证书的 SHA-256 指纹（十六进制）。
//
// Self-signed links include this fingerprint so clients can pin the certificate.
func certFingerprint(certFile string) (string, error) {
	blob, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("读取证书失败: %w", err)
	}
	block, _ := pem.Decode(blob)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("证书不是有效的 PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("解析证书失败: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// 支持的取值。集中在这里，前后端校验共用一份。
var (
	nativeNetworks   = map[string]bool{"tcp": true, "ws": true, "grpc": true, "httpupgrade": true}
	nativeSecurities = map[string]bool{"none": true, "tls": true, "reality": true}
)

// visionCapable 判断能不能用 xtls-rprx-vision。
//
// Vision is valid only for VLESS + TCP + TLS/REALITY.
func visionCapable(protocol, network, security string) bool {
	return protocol == "vless" && network == "tcp" && (security == "tls" || security == "reality")
}
