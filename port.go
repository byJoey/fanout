package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"syscall"
)

// 随机端口的取值范围，落在 IANA 动态端口区间内，避开常见服务。
const (
	randPortMin           = 20000
	randPortMax           = 60000
	inboundPortMinDefault = 50000
	inboundPortMaxDefault = 60000
)

// freeRandomPort 随机挑一个当前空闲的 TCP 端口。
//
// taken 里的端口会被跳过，用于避开本进程已经分配但还没真正监听的端口。
// 实际可用性以能否 bind 为准，这样不会和系统上其他进程抢。
func freeRandomPort(taken map[int]bool) (int, error) {
	return freeRandomPortInRange(taken, randPortMin, randPortMax, "tcp")
}

func freeRandomInboundPort(taken map[int]bool, min, max int, network string) (int, error) {
	return freeRandomPortInRange(taken, min, max, network)
}

func freeRandomPortInRange(taken map[int]bool, min, max int, network string) (int, error) {
	if err := validatePortRange(min, max); err != nil {
		return 0, err
	}
	for i := 0; i < 200; i++ {
		port := min + rand.Intn(max-min+1)
		if taken[port] {
			continue
		}
		if portAvailable(port, network) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("找不到可用端口（已尝试 200 次）")
}

func validatePortRange(min, max int) error {
	if min < 1 || max > 65535 || min > max {
		return fmt.Errorf("端口范围无效：%d-%d", min, max)
	}
	return nil
}

// portAvailable checks both IPv4 and IPv6 for the requested transport.
// A missing IPv6 stack is not treated as an occupied port.
func portAvailable(port int, network string) bool {
	network = strings.ToLower(strings.TrimSpace(network))
	if network != "udp" {
		network = "tcp"
	}
	for _, family := range []string{"4", "6"} {
		if network == "udp" {
			ip := net.IPv4zero
			if family == "6" {
				ip = net.IPv6zero
			}
			udp, err := net.ListenUDP(network+family, &net.UDPAddr{IP: ip, Port: port})
			if err != nil {
				if family == "6" && ipv6Unavailable(err) {
					continue
				}
				return false
			}
			_ = udp.Close()
		} else {
			ln, err := net.Listen(network+family, fmt.Sprintf("%s:%d", listenHost(family), port))
			if err != nil {
				if family == "6" && ipv6Unavailable(err) {
					continue
				}
				return false
			}
			_ = ln.Close()
		}
	}
	return true
}

func listenHost(family string) string {
	if family == "6" {
		return "[::]"
	}
	return "0.0.0.0"
}

func ipv6Unavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || strings.Contains(strings.ToLower(err.Error()), "address family not supported")
}
