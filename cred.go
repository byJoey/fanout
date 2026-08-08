package main

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// credAlphabet 避开容易看错的字符，也避开在 socks5:// URL 里需要转义的符号。
const credAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// 用户名口令的长度限制。RFC1929 的长度字段是单字节，上限 255。
const (
	credUserLen = 6
	credPassLen = 14
	credMaxLen  = 255
)

// newSocksCred 生成一套随机凭据。
func newSocksCred() (SocksCred, error) {
	user, err := randomCredString(credUserLen)
	if err != nil {
		return SocksCred{}, err
	}
	pass, err := randomCredString(credPassLen)
	if err != nil {
		return SocksCred{}, err
	}
	return SocksCred{User: "fo" + user, Pass: pass}, nil
}

func randomCredString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, v := range b {
		out[i] = credAlphabet[int(v)%len(credAlphabet)]
	}
	return string(out), nil
}

// validateCred 校验用户填的凭据。
//
// 不允许空格与冒号：SOCKS5 协议本身不在乎，但 socks5://user:pass@host:port
// 这种写法会被它们拆坏，而客户端基本都用这个格式。
func validateCred(c SocksCred) error {
	if c.User == "" || c.Pass == "" {
		return fmt.Errorf("用户名和口令都不能为空")
	}
	if len(c.User) > credMaxLen || len(c.Pass) > credMaxLen {
		return fmt.Errorf("用户名和口令都不能超过 %d 个字节", credMaxLen)
	}
	for _, field := range []string{c.User, c.Pass} {
		if strings.ContainsAny(field, ": /@\t\r\n") {
			return fmt.Errorf("用户名和口令不能包含空格、冒号、斜杠或 @")
		}
	}
	return nil
}

// socksURL 拼出客户端能直接粘贴的 socks5:// 地址。
func socksURL(host string, port int, cred SocksCred) string {
	if cred.User == "" {
		return fmt.Sprintf("socks5://%s:%d", host, port)
	}
	return fmt.Sprintf("socks5://%s:%s@%s:%d", cred.User, cred.Pass, host, port)
}
