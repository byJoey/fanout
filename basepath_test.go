package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 用户主动去掉路径前缀之后，重启不能又随机出一个新的来。
//
// 之前 LoadBasePath 把"文件存在但内容为空"当成"还没配过"，重新随机了一个。
// 后果是每次重启面板地址都会变，已经分发到客户端的订阅地址也跟着失效。
func TestLoadBasePathKeepsEmptyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "basepath"), []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bp, created, err := LoadBasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("文件已经在，不该重新生成")
	}
	if bp != "" {
		t.Fatalf("空路径应当保持为空，实际 %q", bp)
	}
}

// setBasePath("") 之后重启，路径仍然是空。
func TestEmptyBasePathSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if _, err := initBasePath(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := setBasePath(""); err != nil {
		t.Fatal(err)
	}
	bp, created, err := LoadBasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created || bp != "" {
		t.Fatalf("重启后路径应仍为空，实际 %q (created=%v)", bp, created)
	}
}

// 文件不在时才生成随机路径。
func TestLoadBasePathGeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	bp, created, err := LoadBasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("文件不存在时应当生成路径")
	}
	if len(bp) != 11 { // "/" + 10 个字符
		t.Fatalf("生成的路径长度不对: %q", bp)
	}
	if _, err := os.Stat(filepath.Join(dir, "basepath")); err != nil {
		t.Fatalf("生成的路径应当落盘: %v", err)
	}
}
