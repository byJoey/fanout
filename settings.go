package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// WebSettings 是落盘的可改配置：管理界面的监听端口与地址，外加几个功能开关。
// 界面改完即时生效。访问口令与访问路径各有专门的文件（password / basepath），
// 不放这里，但都能在设置面板里改。
type WebSettings struct {
	// Port 是管理界面监听端口。
	Port int `json:"port"`
	// ListenAddr 是监听地址：空或 0.0.0.0 表示所有网卡；127.0.0.1 表示只本机。
	ListenAddr string `json:"listen_addr"`
	// ResidentialOnly 决定挑节点时是否只用志愿者家宽，跳过 vpngate 自营机房。
	// 用指针是为了区分"没配过"和"明确关掉"：老版本升上来的配置文件里没有这个
	// 字段，nil 按默认的开启处理。
	ResidentialOnly *bool `json:"residential_only,omitempty"`
	// SubToken 是订阅地址里的口令。订阅要免登录才能被客户端拉取，
	// 所以这串就是它唯一的门槛，等同于密码，不要外传。
	SubToken string `json:"sub_token,omitempty"`
	// MaxSlots 是最多同时运行的出口数。0 表示没配过，按命令行 -max 或默认值来。
	MaxSlots int `json:"max_slots,omitempty"`
}

// 出口数上限的取值范围。
//
// 上限 255 是硬约束：槽位号要能塞进网段 10.99.<槽位>，超过就不合法了。
// 下限取 1，再小就没法开出口。
const (
	minMaxSlots = 1
	maxMaxSlots = 200
)

// validateMaxSlots 校验出口数上限。
func validateMaxSlots(n int) error {
	if n < minMaxSlots || n > maxMaxSlots {
		return fmt.Errorf("出口数上限必须在 %d-%d 之间", minMaxSlots, maxMaxSlots)
	}
	return nil
}

// setMaxSlots 改出口数上限并落盘。改完不用重启，调用方负责让 Manager 生效。
func setMaxSlots(n int) error {
	if err := validateMaxSlots(n); err != nil {
		return err
	}
	webSettingsMu.Lock()
	webSettingsCur.MaxSlots = n
	webSettingsMu.Unlock()
	return saveWebSettings()
}

// readStoredMaxSlots 从 settings.json 里读出存过的出口数上限，没存过返回 0。
//
// 单独读一遍是因为 Manager 要在加载设置之前就知道上限，
// 不然恢复旧隧道的时候用的还是命令行默认值。
func readStoredMaxSlots(dir string) int {
	blob, err := os.ReadFile(webSettingsFilePath(dir))
	if err != nil {
		return 0
	}
	var s WebSettings
	if err := json.Unmarshal(blob, &s); err != nil {
		return 0
	}
	return s.MaxSlots
}

// resolveMaxSlots 决定实际生效的出口数上限。
//
// 命令行显式给了 -max 就以命令行为准（跟 -web 一个道理：敲了参数就得算数），
// 否则用面板里存的值，都没配过用默认值。
func resolveMaxSlots(flagVal int, explicit bool, stored int) int {
	if explicit {
		return flagVal
	}
	if stored > 0 {
		return stored
	}
	return flagVal
}

// residentialOnly 返回"只用家宽"是否开启。没配过时默认开：
// fanout 存在的意义就是把家宽扇成出口，机房 IP 对用户没价值。
func (s WebSettings) residentialOnly() bool {
	if s.ResidentialOnly == nil {
		return true
	}
	return *s.ResidentialOnly
}

// residentialOnly 是给业务代码用的简写，省掉每处都去取一遍设置。
func residentialOnly() bool { return getWebSettings().residentialOnly() }

// setResidentialOnly 改"只用家宽"开关并落盘。
func setResidentialOnly(v bool) error {
	webSettingsMu.Lock()
	webSettingsCur.ResidentialOnly = &v
	webSettingsMu.Unlock()
	return saveWebSettings()
}

var (
	webSettingsMu   sync.RWMutex
	webSettingsCur  WebSettings
	webSettingsPath string
)

func webSettingsFilePath(dir string) string { return filepath.Join(dir, "settings.json") }

// loadWebSettings 读盘并返回当前配置。
//
// portExplicit 表示用户在命令行显式给了 -web。界面上改过端口之后会落盘，
// 之前这里一律以盘上为准，导致再带 -web 启动会被静默忽略——用户敲了参数却
// 连不上，也没有任何提示。显式指定时以命令行为准并写回，让参数说话算话。
func loadWebSettings(dir string, defaultPort int, portExplicit bool) (WebSettings, error) {
	webSettingsPath = webSettingsFilePath(dir)

	s := WebSettings{Port: defaultPort, ListenAddr: ""}
	blob, err := os.ReadFile(webSettingsPath)
	switch {
	case os.IsNotExist(err):
		webSettingsMu.Lock()
		webSettingsCur = s
		webSettingsMu.Unlock()
		return s, saveWebSettings()
	case err != nil:
		return s, err
	}
	if err := json.Unmarshal(blob, &s); err != nil {
		return s, err
	}
	if s.Port == 0 {
		s.Port = defaultPort
	}
	changed := false
	if portExplicit && s.Port != defaultPort {
		s.Port = defaultPort
		changed = true
	}
	webSettingsMu.Lock()
	webSettingsCur = s
	webSettingsMu.Unlock()
	if changed {
		return s, saveWebSettings()
	}
	return s, nil
}

func getWebSettings() WebSettings {
	webSettingsMu.RLock()
	defer webSettingsMu.RUnlock()
	return webSettingsCur
}

func saveWebSettings() error {
	webSettingsMu.RLock()
	blob, err := json.MarshalIndent(webSettingsCur, "", "  ")
	webSettingsMu.RUnlock()
	if err != nil {
		return err
	}
	tmp := webSettingsPath + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, webSettingsPath)
}

// normalizeListenAddr 把用户填的监听地址规整成合法值：空 / 0.0.0.0 / 127.0.0.1 / 具体 IP。
func normalizeListenAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "0.0.0.0" || strings.EqualFold(addr, "all") {
		return "", nil
	}
	if ip := net.ParseIP(addr); ip != nil {
		return addr, nil
	}
	return "", fmt.Errorf("监听地址必须是合法 IP，或留空表示所有网卡")
}

// validatePort 校验端口范围。
func validatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("端口必须在 1-65535 之间")
	}
	return nil
}

// listenAddrString 拼出 net.Listen 用的地址串。
func (s WebSettings) listenAddrString() string {
	return net.JoinHostPort(s.ListenAddr, strconv.Itoa(s.Port))
}
