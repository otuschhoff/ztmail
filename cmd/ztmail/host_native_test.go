//go:build native_smoke

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNativeSmokeHostConfiguration(t *testing.T) {
	host, err := platformHostname()
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n\x00") {
		t.Fatalf("native hostname contract failed: %v", err)
	}
	domain, err := platformDomain()
	if err != nil {
		if domain != "" || err.Error() == "" {
			t.Fatal("native domain failure was not explicit")
		}
		t.Log("Native DNS suffix is unavailable; explicit --domain is required.")
	} else if domain == "" {
		if runtime.GOOS != "windows" {
			t.Fatal("empty Unix DNS suffix was not reported as an error")
		}
		t.Log("Windows has no primary DNS suffix; explicit --domain is required.")
	} else if _, err := dnsName(domain); err != nil {
		t.Fatalf("native DNS suffix is invalid: %v", err)
	}
}

func TestNativeSmokeDefaultSenderConfiguration(t *testing.T) {
	path := isolatedSenderConfig(t)
	if !filepath.IsAbs(path) {
		t.Fatal("native configuration path is not absolute")
	}
	for _, value := range []string{"first@corp.example", `"a b"@corp.example`} {
		got, err := writeDefaultSender(value)
		if err != nil || got != path {
			t.Fatalf("native atomic save failed: %v", err)
		}
		saved, err := readDefaultSender()
		if err != nil || saved != value {
			t.Fatalf("native saved sender changed: %q %v", saved, err)
		}
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("native save leaked temporary files: %v", err)
	}
}

func TestNativeSmokePasswordConsoleAvailability(t *testing.T) {
	expected := os.Getenv("ZTMAIL_NATIVE_CONSOLE")
	if expected != "" && expected != "absent" && expected != "present" {
		t.Fatal("ZTMAIL_NATIVE_CONSOLE must be absent or present")
	}
	terminal, err := openPasswordTerminal()
	if err != nil {
		if terminal != nil || err.Error() == "" || expected == "present" {
			t.Fatalf("native console open failed: %v", err)
		}
		t.Log("No native console available; explicit open error verified without prompting.")
		return
	}
	if terminal == nil {
		t.Fatal("native console open returned no terminal and no error")
	}
	if err := terminal.Close(); err != nil {
		t.Fatalf("native console close failed: %v", err)
	}
	if expected == "absent" {
		t.Fatal("native console unexpectedly available in explicitly headless smoke test")
	}
	t.Log("Native console opened and closed; no password read or terminal mode change.")
}
