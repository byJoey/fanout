package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// OpenVPN endpoints require sing-box 1.14 or newer.  Do not pin an exact
// release: later 1.14.x and newer releases may contain important fixes.
const singBoxMinVersion = "1.14.0-alpha.50"

var singBoxVersionRE = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?`)

type singBoxVersionInfo struct {
	major, minor, patch int
	pre                 string
}

func parseSingBoxVersion(text string) (singBoxVersionInfo, bool) {
	line := firstLine(text)
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "sing-box" || fields[1] != "version" {
		return singBoxVersionInfo{}, false
	}
	m := singBoxVersionRE.FindStringSubmatch(fields[2])
	if m == nil {
		return singBoxVersionInfo{}, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	patch, err3 := strconv.Atoi(m[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return singBoxVersionInfo{}, false
	}
	return singBoxVersionInfo{major: major, minor: minor, patch: patch, pre: m[4]}, true
}

func compareSingBoxVersion(a, b singBoxVersionInfo) int {
	for _, pair := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	// A release without a prerelease suffix is newer than any prerelease.
	if a.pre == b.pre {
		return 0
	}
	if a.pre == "" {
		return 1
	}
	if b.pre == "" {
		return -1
	}
	return comparePrerelease(a.pre, b.pre)
}

func comparePrerelease(a, b string) int {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		an, ae := strconv.Atoi(aa[i])
		bn, be := strconv.Atoi(bb[i])
		if ae == nil && be == nil {
			if an < bn {
				return -1
			}
			if an > bn {
				return 1
			}
		} else if ae == nil {
			return -1
		} else if be == nil {
			return 1
		} else if aa[i] < bb[i] {
			return -1
		} else if aa[i] > bb[i] {
			return 1
		}
	}
	if len(aa) < len(bb) {
		return -1
	}
	if len(aa) > len(bb) {
		return 1
	}
	return 0
}

func singBoxCandidates(workDir string) []string {
	return []string{
		filepath.Join(workDir, "bin", "sing-box"),
		"/usr/local/bin/sing-box",
		"/usr/bin/sing-box",
	}
}

func findSingBox(workDir string) (string, error) {
	for _, path := range singBoxCandidates(workDir) {
		if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return path, nil
		}
	}
	if path, err := exec.LookPath("sing-box"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("找不到 sing-box，可执行文件应位于 %s", filepath.Join(workDir, "bin", "sing-box"))
}

// validateSingBox checks the two optional features required by userspace
// OpenVPN endpoints. A distro build with stripped tags would otherwise fail
// only after the first tunnel is created.
func validateSingBox(bin string) error {
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("读取 sing-box 版本失败: %s", trimCommandOutput(out))
	}
	text := string(out)
	got, ok := parseSingBoxVersion(text)
	min, _ := parseSingBoxVersion("sing-box version " + singBoxMinVersion)
	if !ok || compareSingBoxVersion(got, min) < 0 {
		return fmt.Errorf("需要 sing-box >= %s，当前版本信息: %s", singBoxMinVersion, strings.TrimSpace(firstLine(text)))
	}
	for _, tag := range []string{"with_openvpn", "with_gvisor"} {
		if !strings.Contains(text, tag) {
			return fmt.Errorf("sing-box 缺少构建标签 %s", tag)
		}
	}
	return nil
}

func verifySingBoxConfig(bin, cfgPath string) error {
	out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box 配置校验失败: %s", trimCommandOutput(out))
	}
	return nil
}

func writeSingBoxConfig(dir, name string, cfg map[string]any) (string, error) {
	blob, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func trimCommandOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 800 {
		s = s[:800] + "..."
	}
	return s
}

// singBoxProc owns one child process. Tunnel processes are intentionally
// separate from the inbound gateway so replacing one VPN Gate node does not
// interrupt every other exit.
type singBoxProc struct {
	mu   sync.Mutex
	bin  string
	dir  string
	name string
	cmd  *exec.Cmd
	done chan error
}

func (p *singBoxProc) start(cfgPath string) error {
	p.stop()

	logPath := filepath.Join(p.dir, p.name+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("打开 sing-box 日志失败: %w", err)
	}
	cmd := exec.Command(p.bin, "run", "-c", cfgPath)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		f.Close()
		return fmt.Errorf("启动 sing-box 失败: %w", err)
	}

	done := make(chan error, 1)
	p.mu.Lock()
	p.cmd, p.done = cmd, done
	p.mu.Unlock()
	p.writePID(cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		_ = f.Close()
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd = nil
		}
		p.mu.Unlock()
		done <- err
	}()

	select {
	case err := <-done:
		return fmt.Errorf("sing-box 启动后退出: %v，详见 %s", err, logPath)
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func (p *singBoxProc) stop() {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.cmd = nil
	p.done = nil
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		_ = os.Remove(p.pidPath())
		return
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	_ = os.Remove(p.pidPath())
}

func (p *singBoxProc) exited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd == nil
}

func (p *singBoxProc) pidPath() string {
	return filepath.Join(p.dir, p.name+".pid")
}

func (p *singBoxProc) writePID(pid int) {
	_ = os.WriteFile(p.pidPath(), []byte(strconv.Itoa(pid)), 0600)
}

func (p *singBoxProc) reapOrphan() {
	blob, err := os.ReadFile(p.pidPath())
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(blob)))
	if err != nil || pid <= 1 {
		_ = os.Remove(p.pidPath())
		return
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && sameExecutable(exe, p.bin) {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
	}
	_ = os.Remove(p.pidPath())
}

func sameExecutable(a, b string) bool {
	aa, errA := filepath.EvalSymlinks(a)
	bb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && aa == bb
}
