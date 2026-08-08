package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Native is fanout's sing-box-backed inbound manager.
//
// 入站数据存在 native.json，sing-box 的运行配置每次改动后整份重新生成。
// 全量重写比增量改省心：配置是纯函数产物，不会出现改了一半的中间态。
type Native struct {
	mu    sync.Mutex
	dir   string
	store *nativeStore
	proc  *singBoxProc
}

func openNative(workDir string) (*Native, error) {
	if workDir == "" {
		return nil, fmt.Errorf("自建模式缺少工作目录")
	}
	bin, err := findSingBox(workDir)
	if err != nil {
		return nil, err
	}
	if err := validateSingBox(bin); err != nil {
		return nil, err
	}
	store, err := loadNativeStore(workDir)
	if err != nil {
		return nil, err
	}
	// XHTTP is Xray-specific. Keep legacy records visible for deletion, but do
	// not let an old enabled entry prevent the sing-box gateway from starting.
	for _, inbound := range store.Inbounds {
		if inbound.Network == "xhttp" {
			inbound.Enable = false
			if !strings.Contains(inbound.Remark, "XHTTP 不兼容") {
				inbound.Remark += " [XHTTP 不兼容]"
			}
		}
	}
	n := &Native{
		dir:   workDir,
		store: store,
		proc:  &singBoxProc{bin: bin, dir: filepath.Join(workDir, "sing-box"), name: "gateway"},
	}
	// Stop a child left behind by an unclean fanout shutdown.
	n.proc.reapOrphan()
	return n, nil
}

func (n *Native) Kind() string { return "native" }

func (n *Native) Describe() string { return "fanout 自建 sing-box (>=1.14)" }

// apply 重新生成配置并重启 sing-box，然后落盘。
// 调用方必须已持有 n.mu。
func (n *Native) apply(tunnels []*Tunnel) error {
	cfg := buildSingBoxGatewayConfig(n.store.sorted(), tunnels)
	path, err := writeSingBoxConfig(n.proc.dir, n.proc.name, cfg)
	if err != nil {
		return err
	}
	if err := verifySingBoxConfig(n.proc.bin, path); err != nil {
		return err
	}
	// 没有入站时不必留着进程占资源
	if len(cfg["inbounds"].([]any)) == 0 {
		n.proc.stop()
		return n.store.save(n.dir)
	}
	if err := n.proc.start(path); err != nil {
		return err
	}
	return n.store.save(n.dir)
}

// OnTunnelsChanged 在隧道集合变化后重建配置。自建模式下出站直接由隧道列表
// 推导，所以隧道一变就要重新生成，否则新出口没有对应的 socks 出站。
func (n *Native) OnTunnelsChanged(tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.apply(tunnels)
}

// Close 停掉自己拉起的 sing-box。
func (n *Native) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.proc.stop()
}

func (n *Native) Inbounds(live map[string]bool) ([]Inbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	list := n.store.sorted()
	out := make([]Inbound, 0, len(list))
	for _, ib := range list {
		out = append(out, Inbound{
			ID: ib.ID, Port: ib.Port, Protocol: ib.Protocol,
			Remark: ib.Remark, Enable: ib.Enable, Tag: ib.tag(),
			BoundTo: ib.BoundTo, BoundUp: live[ib.BoundTo],
		})
	}
	return out, nil
}

func (n *Native) InboundDetail(id int, publicHost string) (*InboundDetail, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return nil, fmt.Errorf("入站 %d 不存在", id)
	}
	detail := &InboundDetail{
		Inbound: Inbound{
			ID: ib.ID, Port: ib.Port, Protocol: ib.Protocol,
			Remark: ib.Remark, Enable: ib.Enable, Tag: ib.tag(),
			BoundTo: ib.BoundTo,
		},
		Listen:  "0.0.0.0",
		Network: ib.netOrTCP(),
		TLS:     "none",
	}
	for _, c := range ib.Clients {
		id := c.ID
		if ib.Protocol == "trojan" {
			id = c.Password
		}
		detail.Clients = append(detail.Clients, ClientInfo{Email: c.Email, ID: id, Enable: c.Enable})
		detail.Links = append(detail.Links, shareLink(ib, c, publicHost))
	}
	return detail, nil
}

func (n *Native) InboundLinks(ids []int, publicHost string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	var out []string
	for _, id := range ids {
		ib := n.store.byID(id)
		if ib == nil {
			continue
		}
		for _, c := range ib.Clients {
			out = append(out, shareLink(ib, c, publicHost))
		}
	}
	return out, nil
}

func (n *Native) Bind(inboundTag string, hostname string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var target *Tunnel
	if hostname != "" {
		for _, t := range tunnels {
			if t.Node.HostName == hostname {
				target = t
				break
			}
		}
		if target == nil {
			return fmt.Errorf("节点 %s 没有运行中的隧道", hostname)
		}
		if target.Status != "up" {
			return fmt.Errorf("节点 %s 的隧道还没连通（当前 %s）", hostname, target.Status)
		}
	}

	var found *nativeInbound
	for _, ib := range n.store.Inbounds {
		if ib.tag() == inboundTag {
			found = ib
			break
		}
	}
	if found == nil {
		return fmt.Errorf("入站 %s 不存在", inboundTag)
	}

	if target == nil {
		found.BoundTo = ""
	} else {
		found.BoundTo = sanitizeTag(target.Node.HostName)
	}
	return n.apply(tunnels)
}

func (n *Native) Rebind(oldHost string, target *Tunnel, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	oldTag := sanitizeTag(oldHost)
	newTag := sanitizeTag(target.Node.HostName)
	newLabel := exitLabel(target)
	for _, ib := range n.store.Inbounds {
		if ib.BoundTo != oldTag {
			continue
		}
		ib.BoundTo = newTag
		// 备注里带着旧出口的地区和 IP 尾段，换了节点要跟着改
		ib.Remark = renameExitSuffix(ib.Remark, newLabel)
	}
	return n.apply(tunnels)
}

func (n *Native) ResyncOutbound(t *Tunnel, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.apply(tunnels)
}

// CloneToTunnels 以某个入站为模板，为每条指定隧道复制一个入站并绑好出口。
//
// 客户端凭据整套沿用模板：同一个 UUID 能走所有出口，用户只改端口。
func (n *Native) CloneToTunnels(templateID int, hosts []string, tunnels []*Tunnel) ([]int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	tpl := n.store.byID(templateID)
	if tpl == nil {
		return nil, fmt.Errorf("模板入站 %d 不存在", templateID)
	}

	byHost := map[string]*Tunnel{}
	for _, t := range tunnels {
		byHost[t.Node.HostName] = t
	}

	used := n.store.usedPorts()
	created := []int{}
	for _, host := range hosts {
		t := byHost[host]
		if t == nil || t.Status != "up" {
			continue
		}
		port, err := freeRandomPort(used)
		if err != nil {
			return created, err
		}
		used[port] = true

		clone := &nativeInbound{
			ID:       n.store.NextID,
			Port:     port,
			Protocol: tpl.Protocol,
			Network:  tpl.Network,
			Path:     tpl.Path,
			Host:     tpl.Host,
			// 安全层必须跟着复制：漏掉的话从 REALITY/TLS 模板复制出来的
			// 入站会变成明文，而分享链接照样标着模板的协议，很难发现
			Security: tpl.Security,
			TLS:      tpl.TLS,
			Reality:  tpl.Reality,
			Remark:   cloneRemark(tpl.Remark, exitLabel(t)),
			Enable:   true,
			Clients:  append([]nativeClient(nil), tpl.Clients...),
			BoundTo:  sanitizeTag(t.Node.HostName),
		}
		n.store.NextID++
		n.store.Inbounds = append(n.store.Inbounds, clone)
		created = append(created, port)
	}

	if len(created) == 0 {
		return created, fmt.Errorf("没有可用的隧道")
	}
	if err := n.apply(tunnels); err != nil {
		return created, err
	}
	return created, nil
}

func (n *Native) DeleteInbounds(ids []int, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	drop := map[int]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	kept := make([]*nativeInbound, 0, len(n.store.Inbounds))
	for _, ib := range n.store.Inbounds {
		if !drop[ib.ID] {
			kept = append(kept, ib)
		}
	}
	n.store.Inbounds = kept
	return n.apply(tunnels)
}

// UpdateInbound 改端口、备注与启停。
//
// 端口变了 inboundTag 也跟着变（tag 里含端口），所以路由规则要一起重写；
// apply 是整份重建，天然覆盖了这点。
func (n *Native) UpdateInbound(id int, patch InboundPatch, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}

	if patch.Port != nil && *patch.Port != ib.Port {
		port := *patch.Port
		if port < 1 || port > 65535 {
			return fmt.Errorf("端口 %d 不在合法范围", port)
		}
		for _, other := range n.store.Inbounds {
			if other.ID != id && other.Port == port {
				return fmt.Errorf("端口 %d 已被入站 %q 占用", port, other.Remark)
			}
		}
		ib.Port = port
	}
	if patch.Remark != nil {
		if r := strings.TrimSpace(*patch.Remark); r != "" {
			ib.Remark = r
		}
	}
	if patch.Enable != nil {
		ib.Enable = *patch.Enable
	}
	return n.apply(tunnels)
}

// AddClient 给入站加一个客户端。同一入站上可以有多套凭据，便于分发给不同人。
func (n *Native) AddClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}

	email = strings.TrimSpace(email)
	if email == "" {
		email = fmt.Sprintf("%s-%d-%s", ib.Protocol, ib.Port, randomHex(3))
	}
	for _, c := range ib.Clients {
		if c.Email == email {
			return fmt.Errorf("客户端 %q 已存在", email)
		}
	}

	ib.Clients = append(ib.Clients, nativeClient{
		Email:    email,
		ID:       newUUID(),
		Password: randomHex(8),
		Enable:   true,
		Flow:     visionFlow(ib),
	})
	return n.apply(tunnels)
}

// DeleteClient 摘掉一个客户端。留下最后一个是有意的：
// 没有任何客户端的入站虽然合法，但谁也连不上，只会让人以为坏了。
func (n *Native) DeleteClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}
	if len(ib.Clients) <= 1 {
		return fmt.Errorf("这是最后一个客户端，删掉就没人能连了")
	}

	kept := make([]nativeClient, 0, len(ib.Clients))
	for _, c := range ib.Clients {
		if c.Email != email {
			kept = append(kept, c)
		}
	}
	if len(kept) == len(ib.Clients) {
		return fmt.Errorf("客户端 %q 不存在", email)
	}
	ib.Clients = kept
	return n.apply(tunnels)
}

// ResetClient 换一套新凭据，旧链接立即失效。
func (n *Native) ResetClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}
	for i := range ib.Clients {
		if ib.Clients[i].Email == email {
			ib.Clients[i].ID = newUUID()
			ib.Clients[i].Password = randomHex(8)
			return n.apply(tunnels)
		}
	}
	return fmt.Errorf("客户端 %q 不存在", email)
}

// visionFlow 沿用入站已有客户端的 flow，让新加的客户端与其余保持一致。
func visionFlow(ib *nativeInbound) string {
	for _, c := range ib.Clients {
		if c.Flow != "" {
			return c.Flow
		}
	}
	return ""
}

// NewInboundSpec 是自建模式下新建入站的参数。
//
// 留空的字段都有合理默认：端口随机、备注按协议加端口自动生成、
// 路径随机、REALITY 的密钥与 shortId 自动生成。
type NewInboundSpec struct {
	Protocol string
	Network  string
	Port     int
	Remark   string
	Path     string
	Host     string
	Security string
	// Vision 请求给 VLESS 客户端启用 xtls-rprx-vision
	Vision bool

	// TLS：留空 CertFile 就生成自签证书
	ServerName string
	CertFile   string
	KeyFile    string

	// REALITY
	Dest        string
	ServerNames string // 逗号分隔，留空则从 Dest 推出来
	ShortID     string
	Fingerprint string
}

// nativeProtocols 是自建模式支持的协议，与前端下拉保持一致。
var nativeProtocols = map[string]bool{"vless": true, "vmess": true, "trojan": true}

// CreateInbound 新建一个入站，端口留空时随机分配。
func (n *Native) CreateInbound(spec NewInboundSpec, tunnels []*Tunnel) (*CreatedInbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ns, err := normalizeInboundSpec(spec, n.store.usedPorts())
	if err != nil {
		return nil, err
	}
	proto, network, security, port := ns.Protocol, ns.Network, ns.Security, ns.Port

	ib := &nativeInbound{
		ID:       n.store.NextID,
		Port:     port,
		Protocol: proto,
		Network:  network,
		Path:     ns.Path,
		Host:     ns.Host,
		Security: security,
		Remark:   ns.Remark,
		Enable:   true,
	}

	switch security {
	case "tls":
		conf, err := buildTLS(n.dir, spec)
		if err != nil {
			return nil, err
		}
		ib.TLS = conf
	case "reality":
		conf, err := buildReality(n.proc.bin, spec)
		if err != nil {
			return nil, err
		}
		ib.Reality = conf
	}

	ib.Clients = []nativeClient{{
		Email:    fmt.Sprintf("%s-%d", proto, port),
		ID:       newUUID(),
		Password: randomHex(8),
		Flow:     ns.Flow,
		Enable:   true,
	}}

	n.store.NextID++
	n.store.Inbounds = append(n.store.Inbounds, ib)

	if err := n.apply(tunnels); err != nil {
		// 起不来就别把坏入站留在库里
		n.store.Inbounds = n.store.Inbounds[:len(n.store.Inbounds)-1]
		n.store.NextID--
		_ = n.apply(tunnels)
		return nil, err
	}
	return &CreatedInbound{
		ID:       ib.ID,
		Port:     ib.Port,
		Protocol: ib.Protocol,
		Remark:   ib.Remark,
		Network:  ib.netOrTCP(),
		Security: ib.securityOrNone(),
	}, nil
}

// cloneRemark gives copied inbounds a stable, readable name.
func cloneRemark(base, label string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return label
	}
	return base + "-" + label
}

// shareLink 生成客户端可直接导入的分享链接。
func shareLink(ib *nativeInbound, c nativeClient, host string) string {
	net := ib.netOrTCP()
	sec := ib.securityOrNone()

	q := url.Values{}
	q.Set("type", net)
	q.Set("security", sec)

	switch net {
	case "ws", "httpupgrade":
		q.Set("path", ib.Path)
		if ib.Host != "" {
			q.Set("host", ib.Host)
		}
	case "grpc":
		q.Set("serviceName", strings.TrimPrefix(ib.Path, "/"))
	}

	switch sec {
	case "tls":
		if ib.TLS != nil {
			if ib.TLS.ServerName != "" {
				q.Set("sni", ib.TLS.ServerName)
			}
			// 自签证书需要靠指纹让客户端固定信任这一张。
			if ib.TLS.SelfSigned && ib.TLS.CertSha256 != "" {
				q.Set("pinSHA256", ib.TLS.CertSha256)
			}
		}
	case "reality":
		if ib.Reality != nil {
			if len(ib.Reality.ServerNames) > 0 {
				q.Set("sni", ib.Reality.ServerNames[0])
			}
			// pbk 是分享链接的通用写法，各家客户端都认。
			q.Set("pbk", ib.Reality.PublicKey)
			if len(ib.Reality.ShortIDs) > 0 {
				q.Set("sid", ib.Reality.ShortIDs[0])
			}
			if ib.Reality.Fingerprint != "" {
				q.Set("fp", ib.Reality.Fingerprint)
			}
		}
	}

	if c.Flow != "" && ib.Protocol == "vless" {
		q.Set("flow", c.Flow)
	}

	frag := url.PathEscape(ib.Remark)

	switch ib.Protocol {
	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", c.Password, host, ib.Port, q.Encode(), frag)
	case "vmess":
		// vmess 的 base64 形式各家客户端解析不一，用通用的 URI 形式
		q.Set("encryption", "auto")
		return fmt.Sprintf("vmess://%s@%s:%d?%s#%s", c.ID, host, ib.Port, q.Encode(), frag)
	default:
		q.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.ID, host, ib.Port, q.Encode(), frag)
	}
}

// buildTLS 组装 TLS 配置。没给证书路径就生成一张自签的，落在 dir/certs 下。
func buildTLS(dir string, spec NewInboundSpec) (*tlsConfig, error) {
	name := strings.TrimSpace(spec.ServerName)
	if name == "" {
		name = "localhost"
	}
	conf := &tlsConfig{ServerName: name}

	cert, key := strings.TrimSpace(spec.CertFile), strings.TrimSpace(spec.KeyFile)
	// 只填一个多半是漏填，静默退回自签会让用户以为用上了自己的证书
	if (cert == "") != (key == "") {
		return nil, fmt.Errorf("证书和私钥要成对填写，或者都留空用自签证书")
	}
	if cert != "" && key != "" {
		if _, err := os.Stat(cert); err != nil {
			return nil, fmt.Errorf("证书文件不可读: %w", err)
		}
		if _, err := os.Stat(key); err != nil {
			return nil, fmt.Errorf("私钥文件不可读: %w", err)
		}
		conf.CertFile, conf.KeyFile = cert, key
		return conf, nil
	}

	// 自签证书验不过 CA，靠链接里的证书指纹让客户端固定信任
	c, k, err := selfSignedCert(dir, name)
	if err != nil {
		return nil, err
	}
	conf.CertFile, conf.KeyFile, conf.SelfSigned = c, k, true
	// 指纹是自签证书唯一能让客户端验过的凭据，算不出来就没法生成可用链接
	fp, err := certFingerprint(c)
	if err != nil {
		return nil, err
	}
	conf.CertSha256 = fp
	return conf, nil
}

// buildReality 组装 REALITY 配置，密钥和 shortId 都自动生成。
// singBoxBin is used to generate a REALITY key pair.
func buildReality(singBoxBin string, spec NewInboundSpec) (*realityConfig, error) {
	dest := strings.TrimSpace(spec.Dest)
	if dest == "" {
		// REALITY 要跟 dest 完成一次真实 TLS1.3 握手，dest 不稳会让所有连接
		// 静默回落。microsoft.com 在部分机房握手经常走不完，这里选更可靠的。
		dest = "www.tesla.com:443"
	}
	if !strings.Contains(dest, ":") {
		dest += ":443"
	}

	var names []string
	for _, s := range strings.Split(spec.ServerNames, ",") {
		if s = strings.TrimSpace(s); s != "" {
			names = append(names, s)
		}
	}
	if len(names) == 0 {
		// 默认用 dest 的主机名：REALITY 要求 SNI 与被借用的站点一致
		names = []string{strings.SplitN(dest, ":", 2)[0]}
	}

	priv, pub, err := realityKeys(singBoxBin)
	if err != nil {
		return nil, err
	}
	if err := checkRealityDest(dest, names[0]); err != nil {
		return nil, fmt.Errorf("REALITY 目标站点不可用，换一个 dest: %w", err)
	}

	short := strings.TrimSpace(spec.ShortID)
	if short == "" {
		short = randomShortID()
	}
	fp := strings.TrimSpace(spec.Fingerprint)
	if fp == "" {
		fp = "chrome"
	}

	return &realityConfig{
		Dest:        dest,
		ServerNames: names,
		PrivateKey:  priv,
		PublicKey:   pub,
		ShortIDs:    []string{short},
		Fingerprint: fp,
	}, nil
}
