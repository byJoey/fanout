package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withInstance 临时换一套实例标识，测完还原。
func withInstance(t *testing.T, tag string, base int) {
	t.Helper()
	pTag, pBase := instTag, instBase
	instTag, instBase = tag, base
	t.Cleanup(func() { instTag, instBase = pTag, pBase })
}

// 默认工作目录必须保持老名字，否则升级上来的机器会认不出自己之前建的 netns，
// 留下一堆没人清理的残留。
func TestDefaultWorkDirKeepsLegacyNames(t *testing.T) {
	pTag, pBase := instTag, instBase
	t.Cleanup(func() { instTag, instBase = pTag, pBase })

	if err := initInstance(defaultWorkDir); err != nil {
		t.Fatal(err)
	}
	if instTag != "" || instBase != defaultNetBase {
		t.Fatalf("默认目录不该带实例标识，实际 tag=%q base=%d", instTag, instBase)
	}

	tn := &Tunnel{Slot: 3}
	if got := tn.nsName(); got != "fo3" {
		t.Fatalf("netns 名应与老版本一致，实际 %q", got)
	}
	if got := tn.subnet(); got != "10.99.3" {
		t.Fatalf("网段应与老版本一致，实际 %q", got)
	}
	veth, peer := tn.vethNames()
	if veth != "fov3" || peer != "fop3" {
		t.Fatalf("网卡名应与老版本一致，实际 %q/%q", veth, peer)
	}
	// 带结尾斜杠、相对写法也算默认目录
	if err := initInstance(defaultWorkDir + "/"); err != nil {
		t.Fatal(err)
	}
	if instTag != "" {
		t.Fatalf("带斜杠的默认目录也不该带标识，实际 %q", instTag)
	}
}

// 换了工作目录就得有自己一套名字，否则两个实例会互相把 netns 删掉。
func TestOtherWorkDirGetsOwnNames(t *testing.T) {
	pTag, pBase := instTag, instBase
	t.Cleanup(func() { instTag, instBase = pTag, pBase })

	dir := t.TempDir()
	if err := initInstance(dir); err != nil {
		t.Fatal(err)
	}
	if instTag == "" {
		t.Fatal("非默认目录必须带实例标识")
	}
	if instBase == defaultNetBase {
		t.Fatal("非默认目录不能用默认实例的网段")
	}
	if instBase < netBaseMin || instBase > netBaseMax {
		t.Fatalf("网段越界: %d", instBase)
	}

	tn := &Tunnel{Slot: 3}
	if tn.nsName() == "fo3" {
		t.Fatal("netns 名和默认实例撞了")
	}
	if tn.subnet() == "10.99.3" {
		t.Fatal("网段和默认实例撞了")
	}

	// 网卡名有 15 字符上限，超了 ip link add 会直接失败
	veth, peer := tn.vethNames()
	for _, n := range []string{veth, peer} {
		if len(n) > 15 {
			t.Fatalf("网卡名 %q 超过 15 字符", n)
		}
	}
	// 槽位取到上限时也不能超
	big := &Tunnel{Slot: 99}
	v2, p2 := big.vethNames()
	for _, n := range []string{v2, p2} {
		if len(n) > 15 {
			t.Fatalf("槽位 99 时网卡名 %q 超过 15 字符", n)
		}
	}
}

// 网段要落盘，重启后必须还是同一个，否则上次的 netns 没人认领。
func TestNetBaseStableAcrossRestart(t *testing.T) {
	pTag, pBase := instTag, instBase
	t.Cleanup(func() { instTag, instBase = pTag, pBase })

	dir := t.TempDir()
	if err := initInstance(dir); err != nil {
		t.Fatal(err)
	}
	first, firstTag := instBase, instTag

	blob, err := os.ReadFile(filepath.Join(dir, "netbase"))
	if err != nil {
		t.Fatalf("网段没落盘: %v", err)
	}
	if strings.TrimSpace(string(blob)) == "" {
		t.Fatal("网段文件是空的")
	}

	instBase, instTag = 0, ""
	if err := initInstance(dir); err != nil {
		t.Fatal(err)
	}
	if instBase != first || instTag != firstTag {
		t.Fatalf("重启后变了: base %d->%d tag %q->%q", first, instBase, firstTag, instTag)
	}
}

// 两个不同目录不能拿到同一个网段，否则母机侧的 veth 地址会撞、路由互顶。
func TestTwoWorkDirsGetDifferentBases(t *testing.T) {
	pTag, pBase := instTag, instBase
	t.Cleanup(func() { instTag, instBase = pTag, pBase })

	a, b := t.TempDir(), t.TempDir()
	if err := initInstance(a); err != nil {
		t.Fatal(err)
	}
	baseA, tagA := instBase, instTag
	if err := initInstance(b); err != nil {
		t.Fatal(err)
	}
	if instBase == baseA {
		t.Fatalf("两个目录拿到同一个网段 10.%d.x", baseA)
	}
	if instTag == tagA {
		t.Fatalf("两个目录拿到同一个实例标识 %q", tagA)
	}
}

// 坏掉的 netbase 文件不能把服务卡死，重挑一个就行。
func TestNetBaseFileCorrupted(t *testing.T) {
	pTag, pBase := instTag, instBase
	t.Cleanup(func() { instTag, instBase = pTag, pBase })

	dir := t.TempDir()
	for _, junk := range []string{"", "  ", "abc", "42", "999", "-1"} {
		if err := os.WriteFile(filepath.Join(dir, "netbase"), []byte(junk), 0600); err != nil {
			t.Fatal(err)
		}
		if err := initInstance(dir); err != nil {
			t.Fatalf("netbase=%q 时应当重挑而不是报错: %v", junk, err)
		}
		if instBase < netBaseMin || instBase > netBaseMax {
			t.Fatalf("netbase=%q 后网段越界: %d", junk, instBase)
		}
	}
}

func TestShortHashStable(t *testing.T) {
	a := shortHash("/opt/fanout-demo")
	if a != shortHash("/opt/fanout-demo") {
		t.Fatal("同一个目录每次要算出同一个标识")
	}
	if len(a) != 4 {
		t.Fatalf("标识应是 4 位，实际 %q", a)
	}
	if a == shortHash("/opt/fanout-other") {
		t.Fatal("不同目录不该算出同一个标识")
	}
}

// 同一个工作目录不许跑两份：那比抢 netns 更糟，state.json 会互相覆盖。
func TestLockWorkDirRejectsSecond(t *testing.T) {
	dir := t.TempDir()
	release, err := lockWorkDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockWorkDir(dir); err == nil {
		t.Fatal("第二次加锁应当失败")
	} else if !strings.Contains(err.Error(), "-dir") {
		t.Fatalf("报错要告诉用户怎么办，实际: %v", err)
	}
	// 放开之后要能重新拿到，否则重启自己会被自己挡住
	release()
	again, err := lockWorkDir(dir)
	if err != nil {
		t.Fatalf("释放后应能重新加锁: %v", err)
	}
	again()
}

// 不同目录互不影响。
func TestLockWorkDirIndependent(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	ra, err := lockWorkDir(a)
	if err != nil {
		t.Fatal(err)
	}
	defer ra()
	rb, err := lockWorkDir(b)
	if err != nil {
		t.Fatalf("另一个目录不该被挡: %v", err)
	}
	rb()
}

// 已经配在母机上的 10.x 段要避开，免得把人家的路由顶掉。
func TestHostUsedNetBasesIncludesDefault(t *testing.T) {
	used := hostUsedNetBases()
	if !used[defaultNetBase] {
		t.Fatal("默认实例的 99 段必须始终算作已占用")
	}
}
