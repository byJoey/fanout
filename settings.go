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

// WebSettings 是管理界面和入站端口的可改配置：监听端口、监听地址（本地/全接口）、
// 入站随机端口范围。
// 落盘持久化，界面改完重启监听即时生效。访问口令与访问路径各有专门的文件
// （password / basepath），不放这里，但都能在设置面板里改。
type WebSettings struct {
	// Port 是管理界面监听端口。
	Port int `json:"port"`
	// ListenAddr 是监听地址：空或 0.0.0.0 表示所有网卡；127.0.0.1 表示只本机。
	ListenAddr     string `json:"listen_addr"`
	InboundPortMin int    `json:"inbound_port_min"`
	InboundPortMax int    `json:"inbound_port_max"`
}

var (
	webSettingsMu   sync.RWMutex
	webSettingsCur  WebSettings
	webSettingsPath string
)

func webSettingsFilePath(dir string) string { return filepath.Join(dir, "settings.json") }

// loadWebSettings 读盘并返回当前配置。文件不存在时用传入的 flag 默认值建档。
func loadWebSettings(dir string, defaultPort int) (WebSettings, error) {
	webSettingsPath = webSettingsFilePath(dir)

	s := WebSettings{Port: defaultPort, ListenAddr: "", InboundPortMin: inboundPortMinDefault, InboundPortMax: inboundPortMaxDefault}
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
	if s.InboundPortMin == 0 {
		s.InboundPortMin = inboundPortMinDefault
	}
	if s.InboundPortMax == 0 {
		s.InboundPortMax = inboundPortMaxDefault
	}
	if err := validatePortRange(s.InboundPortMin, s.InboundPortMax); err != nil {
		return s, err
	}
	webSettingsMu.Lock()
	webSettingsCur = s
	webSettingsMu.Unlock()
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

func setInboundPortRangeSettings(min, max int) error {
	if err := validatePortRange(min, max); err != nil {
		return err
	}
	webSettingsMu.Lock()
	webSettingsCur.InboundPortMin = min
	webSettingsCur.InboundPortMax = max
	webSettingsMu.Unlock()
	return saveWebSettings()
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
