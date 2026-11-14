//go:build windows && native_smoke

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeSmokeWindowsConsolelessProcess(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestWindowsConsolelessHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "ZTMAIL_TEST_CONSOLELESS_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("consoleless child failed: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
	if !bytes.Contains(output, []byte("--- PASS: TestWindowsConsolelessHelper")) {
		t.Fatalf("consoleless helper did not execute successfully:\n%s", output)
	}
}

func TestWindowsConsolelessHelper(t *testing.T) {
	if os.Getenv("ZTMAIL_TEST_CONSOLELESS_CHILD") != "1" {
		t.Skip("runs only in the explicitly consoleless native-smoke child")
	}
	freeConsole := windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole")
	if result, _, err := freeConsole.Call(); result == 0 {
		t.Fatalf("detach child console: %v", err)
	}
	if cp, err := windows.GetConsoleCP(); cp != 0 || !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("child still has a console or state is unverifiable: codepage=%d err=%v", cp, err)
	}
	terminal, err := openPasswordTerminal()
	if terminal != nil {
		if closeErr := terminal.Close(); closeErr != nil {
			t.Fatalf("close unexpected native console: %v", closeErr)
		}
		t.Fatal("consoleless child unexpectedly opened a native console")
	}
	if err == nil || err.Error() == "" {
		t.Fatal("consoleless native open did not return an explicit error")
	}
}
