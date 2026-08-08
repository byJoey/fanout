package main

import (
	"net"
	"testing"
)

func TestPortAvailableChecksTransportAndFamilies(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcpPort := tcp.Addr().(*net.TCPAddr).Port
	if portAvailable(tcpPort, "tcp") {
		t.Fatalf("TCP 端口 %d 已被 IPv4 占用却被判为空闲", tcpPort)
	}
	if !portAvailable(tcpPort, "udp") {
		t.Fatalf("同端口 UDP 不应被 TCP 占用影响: %d", tcpPort)
	}

	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		t.Skipf("系统没有可用 IPv6 UDP: %v", err)
	}
	defer udp.Close()
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	if portAvailable(udpPort, "udp") {
		t.Fatalf("UDP 端口 %d 已被 IPv6 占用却被判为空闲", udpPort)
	}
	if !portAvailable(udpPort, "tcp") {
		t.Fatalf("同端口 TCP 不应被 UDP 占用影响: %d", udpPort)
	}
}
