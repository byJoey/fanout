package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// 出口数上限的取值范围。
func TestValidateMaxSlots(t *testing.T) {
	for _, n := range []int{1, 20, 30, 200} {
		if err := validateMaxSlots(n); err != nil {
			t.Fatalf("%d 应合法: %v", n, err)
		}
	}
	for _, n := range []int{0, -1, 201, 1000} {
		if err := validateMaxSlots(n); err == nil {
			t.Fatalf("%d 应非法", n)
		}
	}
}

// 命令行显式给的 -max 要压过面板里存的值，反之面板说了算。
func TestResolveMaxSlots(t *testing.T) {
	cases := []struct {
		flagVal  int
		explicit bool
		stored   int
		want     int
	}{
		{20, false, 0, 20},  // 都没配过，用默认值
		{20, false, 30, 30}, // 面板里存了 30
		{50, true, 30, 50},  // 命令行显式给了 50，命令行说话算话
		{20, true, 0, 20},   // 命令行显式给了默认值，也算数
	}
	for _, c := range cases {
		got := resolveMaxSlots(c.flagVal, c.explicit, c.stored)
		if got != c.want {
			t.Fatalf("resolveMaxSlots(%d,%v,%d)=%d，想要 %d",
				c.flagVal, c.explicit, c.stored, got, c.want)
		}
	}
}

// 改了上限要落盘，重启后还在。
func TestSetMaxSlotsPersists(t *testing.T) {
	useSettings(t)
	if err := setMaxSlots(30); err != nil {
		t.Fatal(err)
	}
	if got := getWebSettings().MaxSlots; got != 30 {
		t.Fatalf("设置没落盘: %d", got)
	}
	// 从盘上再读一遍
	if got := readStoredMaxSlots(filepath.Dir(webSettingsPath)); got != 30 {
		t.Fatalf("从盘上读出来不对: %d", got)
	}
}

// 调大上限之后就能再建出口，不用重启。
func TestSetMaxSlotsLetsMoreTunnelsStart(t *testing.T) {
	m := NewManager(2, t.TempDir())
	m.tunnels[1] = &Tunnel{Slot: 1, Status: "up"}
	m.tunnels[2] = &Tunnel{Slot: 2, Status: "up"}

	if _, err := m.freeSlot(); err == nil {
		t.Fatal("两个槽位占满时应当报错")
	}

	m.SetMaxSlots(3)
	if got := m.MaxSlots(); got != 3 {
		t.Fatalf("上限没生效: %d", got)
	}
	slot, err := m.freeSlot()
	if err != nil {
		t.Fatalf("调大之后应当能分到槽位: %v", err)
	}
	if slot != 3 {
		t.Fatalf("应当分到 3 号槽位，实际 %d", slot)
	}
}

// 设置接口改上限：立刻生效、落盘、GET 能读回来。
func TestApiSettingsChangesMaxSlots(t *testing.T) {
	useSettings(t)
	dir := t.TempDir()
	auth, _, err := NewAuth(dir)
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(20, t.TempDir())
	srv := newWebServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h := apiSettings(auth, srv, mgr)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/settings",
		strings.NewReader(`{"max_slots":30}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 %d，正文 %s", rec.Code, rec.Body.String())
	}
	if got := mgr.MaxSlots(); got != 30 {
		t.Fatalf("上限没立即生效: %d", got)
	}
	if got := getWebSettings().MaxSlots; got != 30 {
		t.Fatalf("上限没落盘: %d", got)
	}

	// GET 要能读回来
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if got, _ := out["max_slots"].(float64); int(got) != 30 {
		t.Fatalf("GET 没返回新上限: %v", out["max_slots"])
	}

	// 越界要挡下来，且不能改坏已经生效的值
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/settings",
		strings.NewReader(`{"max_slots":9999}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("越界应当 400，实际 %d", rec.Code)
	}
	if got := mgr.MaxSlots(); got != 30 {
		t.Fatalf("越界之后不该把上限改坏: %d", got)
	}
}
