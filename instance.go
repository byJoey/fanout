package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// 同一台机器上跑两份 fanout 会互相把隧道拆掉。
//
// netns 名、veth 名、子网原来都只按槽位编号生成（fo1 / fov1 / 10.99.1.0/30），
// 两个实例必然重名；而 setupNetns 开头就调 teardownNetns()，
// 于是后起的那个建 fo5 时，顺手把前一个正在用的 fo5 删了——
// 表现为好端端的出口突然"已掉线，正在换节点重连"。
// 独立工作目录、独立端口都挡不住，冲突发生在内核命名空间这一层。
//
// 解法：每个工作目录一套自己的名字。默认目录保持原样，
// 这样已经装好的机器升上来行为完全不变，不用迁移任何东西。

const (
	// defaultWorkDir 是 install.sh 用的目录，绝大多数机器都是它。
	defaultWorkDir = "/var/lib/fanout"
	// defaultNetBase 是子网的第二段，历史上固定 99。
	defaultNetBase = 99
	// netBaseMin/netBaseMax 是给非默认实例留的段，避开 99。
	netBaseMin = 100
	netBaseMax = 255
)

var (
	// instTag 进 netns 与 veth 的名字，默认实例为空串（保持老名字）。
	instTag string
	// instBase 是子网第二段。
	instBase = defaultNetBase
)

// initInstance 定下这个工作目录用哪一套 netns 名与网段。
//
// 结果要落盘：重启后必须还是同一套，否则上一次留下的 netns 没人认领，
// 会一直挂在机器上占着 veth 和 iptables 规则。
func initInstance(workDir string) error {
	abs, err := filepath.Abs(workDir)
	if err != nil {
		abs = workDir
	}
	if filepath.Clean(abs) == defaultWorkDir {
		instTag, instBase = "", defaultNetBase
		return nil
	}

	instTag = shortHash(abs)
	base, err := loadOrPickNetBase(workDir, abs)
	if err != nil {
		return err
	}
	instBase = base
	return nil
}

// shortHash 取一个短而稳定的目录指纹，用作 netns/veth 的名字后缀。
// 只要够区分同机的几个实例就行，不做防碰撞。
func shortHash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%04x", h.Sum32()&0xffff)
}

// loadOrPickNetBase 读盘上记的网段；没有就挑一个空闲的存下来。
func loadOrPickNetBase(workDir, abs string) (int, error) {
	path := filepath.Join(workDir, "netbase")
	if blob, err := os.ReadFile(path); err == nil {
		if n, cerr := strconv.Atoi(strings.TrimSpace(string(blob))); cerr == nil &&
			n >= netBaseMin && n <= netBaseMax {
			return n, nil
		}
	}

	base, err := pickNetBase(abs)
	if err != nil {
		return 0, err
	}
	if werr := os.WriteFile(path, []byte(strconv.Itoa(base)+"\n"), 0600); werr != nil {
		return 0, fmt.Errorf("记录网段失败: %w", werr)
	}
	return base, nil
}

// pickNetBase 挑一个 10.<base>.x.x 段，避开机器上已经在用的。
//
// 先按目录指纹算个起点，这样同一个目录每次都优先拿到同一段；
// 撞上了就往后顺延，所以两个实例即便指纹相近也不会共用网段。
func pickNetBase(abs string) (int, error) {
	used := hostUsedNetBases()
	h := fnv.New32a()
	_, _ = h.Write([]byte(abs))
	span := netBaseMax - netBaseMin + 1
	start := int(h.Sum32()) % span

	for i := 0; i < span; i++ {
		b := netBaseMin + (start+i)%span
		if !used[b] {
			return b, nil
		}
	}
	return 0, fmt.Errorf("10.100.x 到 10.255.x 都被占用了，腾一个出来再启动")
}

// hostUsedNetBases 收集母机上已经配出去的 10.X 段。
//
// 这既能避开另一个 fanout 实例，也能避开机器上本来就有的 10.x 网络
// （容器网桥、别的 VPN），免得配上去把人家的路由顶掉。
func hostUsedNetBases() map[int]bool {
	used := map[int]bool{defaultNetBase: true}
	out, err := exec.Command("ip", "-4", "-o", "addr", "show").Output()
	if err != nil {
		return used
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "inet" || i+1 >= len(fields) {
				continue
			}
			addr := fields[i+1]
			if idx := strings.IndexByte(addr, '/'); idx > 0 {
				addr = addr[:idx]
			}
			parts := strings.Split(addr, ".")
			if len(parts) != 4 || parts[0] != "10" {
				continue
			}
			if n, cerr := strconv.Atoi(parts[1]); cerr == nil {
				used[n] = true
			}
		}
	}
	return used
}

// lockWorkDir 保证一个工作目录同时只有一个 fanout 在用。
//
// 两份共用同一个目录比抢 netns 更糟：state.json 会互相覆盖，
// 隧道记录直接丢。锁是进程级的，进程没了内核自动释放，不会留下死锁文件。
func lockWorkDir(dir string) (func(), error) {
	path := filepath.Join(dir, "lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("打开锁文件失败: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("另一个 fanout 正在用工作目录 %s；"+
			"要同时跑第二个实例，给它一个不同的 -dir", dir)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
