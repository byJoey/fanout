package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 最小实现：只支持 CONNECT。
// 域名在本进程内解析，隧道里只跑 TCP，避免依赖隧道内的 UDP/DNS。
//
// 认证走 RFC1929 用户名/口令。端口对公网敞开，没有口令等于谁扫到谁就能用
// 这条家宽出口，所以凭据是必需的而不是可选项。

const (
	socksVer5     = 0x05
	authNone      = 0x00
	authUserPass  = 0x02
	authNoAccept  = 0xff
	authSubVer    = 0x01
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repGenFail    = 0x01
	repHostUnre   = 0x04
	repCmdNotSupp = 0x07
)

// serveSocks 处理一条 SOCKS5 连接。dial 决定流量从哪条链路出去。
// cred 为 nil 时不要求认证（内部调用路径不会走到，这里只是兜底）。
func serveSocks(client net.Conn, cred *SocksCred, dial func(network, addr string) (net.Conn, error)) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socksHandshake(client, cred); err != nil {
		return
	}

	addr, err := socksReadRequest(client)
	if err != nil {
		if errors.Is(err, errCmdNotSupported) {
			socksReply(client, repCmdNotSupp)
		} else {
			socksReply(client, repGenFail)
		}
		return
	}

	remote, err := dial("tcp", addr)
	if err != nil {
		socksReply(client, repHostUnre)
		return
	}
	defer remote.Close()

	if err := socksReply(client, repSuccess); err != nil {
		return
	}

	// 转发阶段不设整体超时，交给两端自然关闭
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	relay(client, remote)
}

// socksHandshake 完成方法协商，需要认证时接着跑一轮 RFC1929。
func socksHandshake(c net.Conn, cred *SocksCred) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[0] != socksVer5 {
		return errors.New("不是 socks5")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	if cred == nil || cred.User == "" {
		_, err := c.Write([]byte{socksVer5, authNone})
		return err
	}

	// 客户端没提用户名口令就直接拒绝，不退回无认证
	if !bytes.ContainsRune(methods, rune(authUserPass)) {
		_, _ = c.Write([]byte{socksVer5, authNoAccept})
		return errors.New("客户端不支持用户名口令认证")
	}
	if _, err := c.Write([]byte{socksVer5, authUserPass}); err != nil {
		return err
	}
	return socksAuth(c, cred)
}

// socksAuth 跑一轮 RFC1929 用户名/口令子协商。
func socksAuth(c net.Conn, cred *SocksCred) error {
	ver := make([]byte, 1)
	if _, err := io.ReadFull(c, ver); err != nil {
		return err
	}
	if ver[0] != authSubVer {
		return errors.New("认证子协议版本不对")
	}
	user, err := readLenPrefixed(c)
	if err != nil {
		return err
	}
	pass, err := readLenPrefixed(c)
	if err != nil {
		return err
	}

	// 恒定时间比较，避免按字节比对泄漏口令长度与前缀
	okUser := subtle.ConstantTimeCompare(user, []byte(cred.User)) == 1
	okPass := subtle.ConstantTimeCompare(pass, []byte(cred.Pass)) == 1
	if !okUser || !okPass {
		_, _ = c.Write([]byte{authSubVer, 0x01})
		return errors.New("用户名或口令不对")
	}
	_, err = c.Write([]byte{authSubVer, 0x00})
	return err
}

// readLenPrefixed 读一个单字节长度前缀的字段。
func readLenPrefixed(c net.Conn) ([]byte, error) {
	l := make([]byte, 1)
	if _, err := io.ReadFull(c, l); err != nil {
		return nil, err
	}
	b := make([]byte, int(l[0]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

var errCmdNotSupported = errors.New("仅支持 CONNECT")

// errIPv6NotSupported 表示拒绝 IPv6 目标：隧道内只有 IPv4。
var errIPv6NotSupported = errors.New("隧道内不支持 IPv6")

func socksReadRequest(c net.Conn) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", err
	}
	if head[1] != cmdConnect {
		return "", errCmdNotSupported
	}

	var host string
	switch head[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		// 隧道内没有 IPv6 路由，放行只会让这条连接绕开隧道
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return "", errIPv6NotSupported
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", fmt.Errorf("不支持的地址类型 %d", head[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))), nil
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVer5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// dialSOCKS5 opens one CONNECT stream through an unauthenticated local SOCKS5
// listener. Tunnel-facing sing-box instances listen only on loopback; fanout's
// public listener remains responsible for client authentication.
func dialSOCKS5(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))

	if _, err := c.Write([]byte{socksVer5, 0x01, authNone}); err != nil {
		return fail(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(c, method); err != nil {
		return fail(err)
	}
	if method[0] != socksVer5 || method[1] != authNone {
		return fail(fmt.Errorf("内部 SOCKS5 拒绝无认证连接"))
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fail(fmt.Errorf("目标端口无效: %q", portText))
	}
	req := []byte{socksVer5, cmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, atypIPv4)
			req = append(req, v4...)
		} else {
			return fail(errIPv6NotSupported)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fail(fmt.Errorf("目标主机名长度无效"))
		}
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return fail(err)
	}
	if head[0] != socksVer5 || head[1] != repSuccess {
		return fail(fmt.Errorf("内部 SOCKS5 连接失败，响应码 %#x", head[1]))
	}
	var addrLen int
	switch head[3] {
	case atypIPv4:
		addrLen = 4
	case atypIPv6:
		addrLen = 16
	case atypDomain:
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			return fail(err)
		}
		addrLen = int(b[0])
	default:
		return fail(fmt.Errorf("内部 SOCKS5 返回未知地址类型 %#x", head[3]))
	}
	if _, err := io.CopyN(io.Discard, c, int64(addrLen+2)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
