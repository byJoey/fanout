package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// basePathAlphabet 避开容易看错的字符。
const basePathAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// 访问路径做成可在运行时改：StripBasePath 每次请求读当前值，
// 设置面板改完立即生效，不用重启。
var (
	basePathMu  sync.RWMutex
	basePathCur string
	basePathDir string
)

// initBasePath 载入访问路径并记住工作目录，供后续修改落盘。
func initBasePath(dir string) (bool, error) {
	bp, created, err := LoadBasePath(dir)
	if err != nil {
		return false, err
	}
	basePathMu.Lock()
	basePathCur = bp
	basePathDir = dir
	basePathMu.Unlock()
	return created, nil
}

// currentBasePath 返回当前访问路径（形如 /xxx 或空）。
func currentBasePath() string {
	basePathMu.RLock()
	defer basePathMu.RUnlock()
	return basePathCur
}

// setBasePath 校验并保存新的访问路径，立即生效。空串表示不加路径前缀。
func setBasePath(raw string) (string, error) {
	bp := normalizeBasePath(raw)
	if bp != "" {
		// 用户手填的路径放宽到任意字母数字加 - _，不套用自动生成时刻意避开的
		// 易混字符集（那套是给随机生成用的）。
		for _, c := range strings.TrimPrefix(bp, "/") {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return "", fmt.Errorf("访问路径只能用字母、数字、- 和 _")
			}
		}
	}
	basePathMu.RLock()
	dir := basePathDir
	basePathMu.RUnlock()
	if err := os.WriteFile(filepath.Join(dir, "basepath"), []byte(strings.TrimPrefix(bp, "/")+"\n"), 0600); err != nil {
		return "", fmt.Errorf("写访问路径失败: %w", err)
	}
	basePathMu.Lock()
	basePathCur = bp
	basePathMu.Unlock()
	return bp, nil
}

// LoadBasePath 读取或生成随机访问路径，形如 /aB3xY9pQ。
// 路径本身也是一层门槛，扫端口的探不到界面。
func LoadBasePath(dir string) (string, bool, error) {
	path := filepath.Join(dir, "basepath")

	blob, err := os.ReadFile(path)
	if err == nil {
		if bp := strings.TrimSpace(string(blob)); bp != "" {
			return normalizeBasePath(bp), false, nil
		}
	} else if !os.IsNotExist(err) {
		return "", false, err
	}

	bp, err := randomBasePath(10)
	if err != nil {
		return "", false, err
	}
	if err := os.WriteFile(path, []byte(bp+"\n"), 0600); err != nil {
		return "", false, fmt.Errorf("写访问路径失败: %w", err)
	}
	return normalizeBasePath(bp), true, nil
}

func randomBasePath(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, v := range b {
		out[i] = basePathAlphabet[int(v)%len(basePathAlphabet)]
	}
	return string(out), nil
}

// normalizeBasePath 统一成 /xxx 的形式（无结尾斜杠）。
func normalizeBasePath(bp string) string {
	bp = strings.Trim(bp, "/")
	if bp == "" {
		return ""
	}
	return "/" + bp
}

// StripBasePath 把请求剥掉前缀后交给内层 handler。
// 前缀不匹配的请求一律 404，不泄漏这里跑着什么服务。
// 每次请求读当前 basePath，改路径后无需重启即可生效。
func StripBasePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := currentBasePath()
		if base == "" {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case r.URL.Path == base:
			// 少了结尾斜杠时补上，否则页面里的相对路径会拼错
			http.Redirect(w, r, base+"/", http.StatusTemporaryRedirect)
		case strings.HasPrefix(r.URL.Path, base+"/"):
			r.URL.Path = strings.TrimPrefix(r.URL.Path, base)
			next.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
