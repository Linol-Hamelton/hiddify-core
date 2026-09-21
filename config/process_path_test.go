package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestExpandProcessPathsKeepsWhatItCannotResolve(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-app.exe")

	got := expandProcessPaths([]string{missing})

	if !reflect.DeepEqual(got, []string{missing}) {
		t.Errorf("expandProcessPaths(%q) = %#v, want the path unchanged", missing, got)
	}
}

func TestExpandProcessPathsDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.exe")

	got := expandProcessPaths([]string{path, path})

	if len(got) != 1 {
		t.Errorf("expandProcessPaths returned %#v, want one entry", got)
	}
}

// The router compares process paths case-sensitively while Windows does not,
// so a rule spelled differently from the image on disk has to keep matching.
func TestExpandProcessPathsAddsTheOnDiskSpelling(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-insensitive path matching is a Windows problem")
	}

	dir := t.TempDir()
	onDisk := filepath.Join(dir, "CurlBlocked.exe")
	if err := os.WriteFile(onDisk, []byte("not a real binary"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	misspelled := filepath.Join(dir, "curlblocked.exe")

	got := expandProcessPaths([]string{misspelled})

	if len(got) != 2 {
		t.Fatalf("expandProcessPaths(%q) = %#v, want the given path and the on-disk one", misspelled, got)
	}
	if got[0] != misspelled {
		t.Errorf("first entry = %q, want the path as configured %q", got[0], misspelled)
	}
	if !strings.HasSuffix(got[1], "CurlBlocked.exe") {
		t.Errorf("second entry = %q, want it to end in the on-disk spelling CurlBlocked.exe", got[1])
	}
}

func TestExpandProcessPathsLeavesAMatchingPathAlone(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-insensitive path matching is a Windows problem")
	}

	dir := t.TempDir()
	onDisk := filepath.Join(dir, "CurlBlocked.exe")
	if err := os.WriteFile(onDisk, []byte("not a real binary"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := expandProcessPaths([]string{onDisk})

	if len(got) != 1 {
		t.Errorf("expandProcessPaths(%q) = %#v, want the single already-correct path", onDisk, got)
	}
}

func TestMakeRuleExpandsProcessPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-insensitive path matching is a Windows problem")
	}

	dir := t.TempDir()
	onDisk := filepath.Join(dir, "CurlBlocked.exe")
	if err := os.WriteFile(onDisk, []byte("not a real binary"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	misspelled := filepath.Join(dir, "curlblocked.exe")

	rule := (&Rule{ProcessPath: []string{misspelled}, Outbound: "block"}).MakeRule()

	if len(rule.ProcessPath) != 2 {
		t.Fatalf("rule.ProcessPath = %#v, want both spellings", rule.ProcessPath)
	}
}

func TestCanonicalWindowsPathRejectsRelativePaths(t *testing.T) {
	if _, err := canonicalWindowsPath("curl.exe"); err == nil {
		t.Error("expected an error for a path with no drive letter")
	}
}
