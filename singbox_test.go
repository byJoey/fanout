package main

import "testing"

func TestCompareSingBoxVersion(t *testing.T) {
	min, _ := parseSingBoxVersion("sing-box version " + singBoxMinVersion)
	tests := []struct {
		version string
		want    int
	}{
		{"1.13.9", -1},
		{"1.14.0-alpha.49", -1},
		{"1.14.0-alpha.50", 0},
		{"1.14.0-alpha.51", 1},
		{"1.14.1", 1},
		{"1.15.0", 1},
	}
	for _, tc := range tests {
		got, ok := parseSingBoxVersion("sing-box version " + tc.version)
		if !ok {
			t.Fatalf("parse %s failed", tc.version)
		}
		cmp := compareSingBoxVersion(got, min)
		if (cmp < 0 && tc.want >= 0) || (cmp == 0 && tc.want != 0) || (cmp > 0 && tc.want <= 0) {
			t.Errorf("compare %s to minimum: got %d, want sign %d", tc.version, cmp, tc.want)
		}
	}
}
