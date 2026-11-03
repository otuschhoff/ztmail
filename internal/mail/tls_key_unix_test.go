//go:build !windows

package mail

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrivateKeyFIFORejectedWithoutWaitingForWriter(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "client.pem"), filepath.Join(directory, "key.fifo")
	cert := testClientCertificate(t)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientCertificate(certPath, keyPath); err == nil || !strings.Contains(err.Error(), "regular owner-private file") {
		t.Fatalf("private-key FIFO was not explicitly rejected: %v", err)
	}
}
