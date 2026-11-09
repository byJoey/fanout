package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// SOCKS5 出口订阅：把母机上的 SOCKS5 端口聚成一条地址，客户端一次拉走全部出口。
//
// 和节点链接订阅（/sub）是两回事，别混：
//
//	/sub    给的是 VLESS/VMess/Trojan 这类入站节点，客户端用自己那套协议栈去连；
//	/socks  给的是母机的 SOCKS5 端口，客户端把它当普通代理用，协议栈不参与。
//
// 两者都是每次请求现生成的，所以新增出口、删除出口之后，
// 客户端下次拉订阅自己就跟上，不用重新配地址。
//
// 访问控制跟 /sub 一致：免登录路径 + 一串独立口令，且仍挂在访问路径下面。

// socksSubEntry 是订阅里的一个出口条目。
type socksSubEntry struct {
	Name string // 给人看的名字，国家 + 出口 IP 末段
	Host string // 母机地址（客户端真正能连上的那个）
	Port int    // 母机上的 SOCKS5 端口
	User string // SOCKS5 用户名
	Pass string // SOCKS5 口令
}

// socksSubEntries 收集当前可用的出口。
//
// 只收 status == "up" 的：连接中的隧道端口还没通、停掉的隧道已经不听了，
// 把它们塞进订阅会让客户端拿到一堆连不上的条目。
func socksSubEntries(m *Manager, host string) []socksSubEntry {
	tunnels := m.Tunnels()
	out := make([]socksSubEntry, 0, len(tunnels))
	for _, t := range tunnels {
		if t.Status != "up" {
			continue
		}
		cred := t.credential()
		out = append(out, socksSubEntry{
			Name: socksEntryName(t),
			Host: host,
			Port: t.Port,
			User: cred.User,
			Pass: cred.Pass,
		})
	}
	return out
}

// socksEntryName 给出口起个名字。
//
// 跟面板上那一行保持一致："🇺🇸 美国 · vpn584855640"——
// 国旗加国家，后面跟上 VPN Gate 的节点主机名。节点名能对上节点，
// 换个节点别名跟着变，一眼能看出这条出口现在走的是哪个节点。
func socksEntryName(t *Tunnel) string {
	label := nodeLabel(t.Node)
	host := strings.TrimSpace(t.Node.HostName)
	if label == "" {
		label = host
	}
	if label == "" || host == "" {
		return label
	}
	return label + " · " + host
}

// socksSubNames 保证名字唯一：重名的补上端口号。
func socksSubNames(entries []socksSubEntry) []string {
	names := make([]string, 0, len(entries))
	used := map[string]bool{}
	for _, e := range entries {
		name := e.Name
		if used[name] {
			name = fmt.Sprintf("%s :%d", e.Name, e.Port)
		}
		// 端口也撞了就再加序号，保证一定不重名
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s :%d-%d", e.Name, e.Port, i)
		}
		used[name] = true
		names = append(names, name)
	}
	return names
}

// socksPath 是 SOCKS5 订阅地址在当前访问路径下的相对部分。
func socksPath(tok string) string {
	return currentBasePath() + "/socks?token=" + tok
}

// socksFullURL 按当前请求推断一个完整地址。
func socksFullURL(r *http.Request, tok string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		if ip := hostPublicIP(); ip != "" {
			host = ip + ":" + fmt.Sprint(getWebSettings().Port)
		}
	}
	return scheme + "://" + host + socksPath(tok)
}

// handleSocksSub 是 SOCKS5 出口订阅本体。走的是免登录路径，所以第一件事是验口令。
//
// 参数：
//
//	token  必填，订阅口令（跟节点链接订阅共用同一串）
//	target 输出格式：base64（默认）、links（明文）、clash（YAML 配置）
//	host   出口地址，默认用母机公网 IP
func handleSocksSub(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		want, err := subToken()
		if err != nil {
			http.Error(w, "订阅口令未就绪", http.StatusInternalServerError)
			return
		}
		// 口令不对就当这个地址不存在，不告诉对方这儿有个订阅服务
		a := sha256.Sum256([]byte(want))
		b := sha256.Sum256([]byte(q.Get("token")))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			http.NotFound(w, r)
			return
		}

		target := strings.ToLower(strings.TrimSpace(q.Get("target")))
		switch target {
		case "", "base64", "b64":
			target = "base64"
		case "links", "plain", "text":
			target = "links"
		case "clash", "yaml", "mihomo":
			target = "clash"
		default:
			http.Error(w, "target 只支持 base64、links 或 clash", http.StatusBadRequest)
			return
		}

		host := q.Get("host")
		if host == "" {
			host = publicHost(r)
		}

		entries := socksSubEntries(m, host)
		if len(entries) == 0 {
			// 回 404 而不是空串：客户端遇到空订阅会把已有节点清空，
			// 非 200 则保留上一份，比被清光好。
			http.Error(w, "还没有可用的出口，先开一条隧道", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// 出口增删比节点链接频繁，一小时拉一次够用
		w.Header().Set("Profile-Update-Interval", "1")
		w.Header().Set("Content-Disposition", "inline; filename=fanout-socks")
		_, _ = w.Write([]byte(encodeSocksSub(entries, target)))
	}
}

// encodeSocksSub 把出口列表转成订阅正文。
//
// base64 是各家客户端的通用吃法：整份文本一次编码，不是逐行。
func encodeSocksSub(entries []socksSubEntry, target string) string {
	if target == "clash" {
		return encodeClashSocks(entries)
	}
	names := socksSubNames(entries)
	links := make([]string, 0, len(entries))
	for i, e := range entries {
		links = append(links, socksSubURI(e, names[i]))
	}
	body := strings.Join(links, "\n")
	if target == "base64" {
		return base64.StdEncoding.EncodeToString([]byte(body))
	}
	return body
}

// socksSubURI 拼一条带别名的 socks5:// 地址。
//
// socks5:// 这个格式本身没有名字字段，光有它客户端只能显示地址和端口。
// 惯例是把别名挂在 URI 的片段（# 后面）上，vless://、trojan:// 都是这么带的，
// 认这个约定的客户端就会拿它当节点名显示。
func socksSubURI(e socksSubEntry, name string) string {
	base := socksURL(e.Host, e.Port, SocksCred{User: e.User, Pass: e.Pass})
	if name == "" {
		return base
	}
	return base + "#" + socksSubEscape(name)
}

// socksSubEscape 转义别名里会破坏解析的字符。
//
// 只动三个：空格（客户端可能按空白切）、#（会被当成片段分隔符）、%（避免歧义）。
// 国旗 emoji 和中文原样留着，客户端不解码也能正常显示；解码的话也不受影响。
func socksSubEscape(name string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "#", "%23").Replace(name)
}

// encodeClashSocks 出 Clash / Mihomo 的 YAML 配置。
//
// 只出 proxies 段是不够的：Clash 系客户端要读到 proxy-groups 和 rules
// 才肯用这份配置，所以这里给一份能直接用的最小配置。
func encodeClashSocks(entries []socksSubEntry) string {
	names := socksSubNames(entries)

	var b strings.Builder
	b.WriteString("mixed-port: 7890\n")
	b.WriteString("allow-lan: false\n")
	b.WriteString("mode: rule\n")
	b.WriteString("log-level: info\n")
	b.WriteString("proxies:\n")
	for i, e := range entries {
		b.WriteString("  - name: " + yamlQuote(names[i]) + "\n")
		b.WriteString("    type: socks5\n")
		b.WriteString("    server: " + yamlQuote(e.Host) + "\n")
		b.WriteString("    port: " + strconv.Itoa(e.Port) + "\n")
		if e.User != "" {
			b.WriteString("    username: " + yamlQuote(e.User) + "\n")
			b.WriteString("    password: " + yamlQuote(e.Pass) + "\n")
		}
		// fanout 的 SOCKS5 支持 UDP ASSOCIATE，交给客户端用上
		b.WriteString("    udp: true\n")
	}

	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: " + yamlQuote("出口") + "\n")
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	for _, n := range names {
		b.WriteString("      - " + yamlQuote(n) + "\n")
	}
	b.WriteString("rules:\n")
	b.WriteString("  - MATCH," + yamlQuote("出口") + "\n")
	return b.String()
}

// yamlQuote 把字符串写成 YAML 的双引号形式。
//
// 名字里有国旗 emoji、中文、冒号（端口号那种），不加引号会被 YAML 误读，
// 所以统一加双引号并转义里面的引号和反斜杠。
func yamlQuote(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"")
	return "\"" + r.Replace(s) + "\""
}
