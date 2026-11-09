package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// 订阅：把 fanout 管着的节点链接聚成一条地址，客户端订阅一次就全有了。
//
// 为什么需要它：一次批量开 5 个家宽出口就是 5 个入站、5 条链接，
// 手动一条条复制粘贴到客户端太笨。而且换节点时端口和客户端配置不变，
// 订阅地址一次配好就不用再动，出口增删会自己跟上。
//
// 访问控制：客户端拉订阅时不可能带登录态，所以 /sub 绕过了登录，
// 改用一串独立口令当门槛。它仍然在访问路径（basepath）后面，
// 等于两层：路径猜不到 + 口令猜不到。

// subTokenLen 是订阅口令的字节数，hex 之后是 40 个字符。
const subTokenLen = 20

// subToken 返回当前订阅口令，没有就生成一串并落盘。
func subToken() (string, error) {
	if tok := strings.TrimSpace(getWebSettings().SubToken); tok != "" {
		return tok, nil
	}
	return resetSubToken()
}

// resetSubToken 换一串新的订阅口令。旧地址立即失效，
// 已经订阅过的客户端要重新配。
func resetSubToken() (string, error) {
	tok, err := randomToken(subTokenLen)
	if err != nil {
		return "", err
	}
	webSettingsMu.Lock()
	webSettingsCur.SubToken = tok
	webSettingsMu.Unlock()
	if err := saveWebSettings(); err != nil {
		return "", err
	}
	return tok, nil
}

// subPath 是订阅地址在当前访问路径下的相对部分，形如 /aB3xY9pQ/sub?token=xxx。
func subPath(tok string) string {
	return currentBasePath() + "/sub?token=" + tok
}

// subFullURL 按当前请求推断一个完整地址。界面上更准的做法是用
// location.origin 拼 subPath，这里只是给不走浏览器的调用方兜底。
func subFullURL(r *http.Request, tok string) string {
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
	return scheme + "://" + host + subPath(tok)
}

// apiSub 给界面用：返回订阅地址。
//
// 一次给全两种订阅：节点链接（/sub）和 SOCKS5 出口（/socks）。
// 两者共用同一串口令，界面上一并显示出来，省得用户自己拼地址。
func apiSub(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, err := subToken()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"token":       tok,
			"path":        subPath(tok),
			"url":         subFullURL(r, tok),
			"socks_path":  socksPath(tok),
			"socks_url":   socksFullURL(r, tok),
			"socks_count": len(socksSubEntries(m, publicHost(r))),
		})
	}
}

// apiSubReset 换一串新口令，旧订阅地址立刻作废。
func apiSubReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只接受 POST"})
		return
	}
	tok, err := resetSubToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"path":       subPath(tok),
		"url":        subFullURL(r, tok),
		"socks_path": socksPath(tok),
		"socks_url":  socksFullURL(r, tok),
	})
}

// subLinks 收集要放进订阅的节点链接。
//
// boundOnly=true 只要绑在出口上的入站。这是默认行为：订阅的意义是
// "一条地址拿到我所有家宽出口"，把走直连的入站混进去会让人以为那些也是家宽。
func subLinks(m *Manager, host string, boundOnly bool) ([]string, error) {
	p, err := openPanel()
	if err != nil {
		return nil, err
	}

	var ids []int
	if boundOnly {
		for _, e := range m.ExitsOf().Exits {
			for _, ib := range e.Inbounds {
				if ib.Enable {
					ids = append(ids, ib.ID)
				}
			}
		}
	} else {
		list, lerr := p.Inbounds(nil)
		if lerr != nil {
			return nil, lerr
		}
		for _, ib := range list {
			if ib.Enable {
				ids = append(ids, ib.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return p.InboundLinks(ids, host)
}

// handleSub 是订阅本体。走的是免登录路径，所以第一件事是验口令。
//
// 参数：
//
//	token  必填，订阅口令
//	target 输出格式：base64（默认，通用）或 links（明文，排查用）
//	host   节点链接里的连接地址，默认用母机公网 IP
//	bound  0 表示把没绑出口的入站也放进来
func handleSub(m *Manager) http.HandlerFunc {
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
		case "", "base64", "b64", "v2ray":
			target = "base64"
		case "links", "plain", "text":
			target = "links"
		default:
			http.Error(w, "target 只支持 base64 或 links", http.StatusBadRequest)
			return
		}

		host := q.Get("host")
		if host == "" {
			host = publicHost(r)
		}
		links, err := subLinks(m, host, q.Get("bound") != "0")
		if err != nil {
			// 节点后端不给链接（xray-cf-lite 模式下链接由它自己的订阅负责）
			http.Error(w, "生成订阅失败: "+firstLine(err.Error()), http.StatusBadGateway)
			return
		}
		if len(links) == 0 {
			// 回 404 而不是空串：客户端遇到空订阅会把已有节点清空，
			// 非 200 则保留上一份，比被清光好。
			http.Error(w, "还没有可订阅的节点，先开出口并建节点链接", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// 客户端据此决定多久自动拉一次；出口增删之外的变化不影响链接，12 小时够
		w.Header().Set("Profile-Update-Interval", "12")
		w.Header().Set("Content-Disposition", "inline; filename=fanout")
		_, _ = w.Write([]byte(encodeSub(links, target)))
	}
}

// encodeSub 把链接列表转成订阅正文。
//
// base64 是各家客户端的通用吃法：整份文本一次编码，不是逐行。
func encodeSub(links []string, target string) string {
	body := strings.Join(links, "\n")
	if target == "base64" {
		return base64.StdEncoding.EncodeToString([]byte(body))
	}
	return body
}
