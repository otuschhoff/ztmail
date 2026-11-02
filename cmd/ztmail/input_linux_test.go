package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSIGINTWhileWaitingForMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSIGINTMessageHelper$")
	cmd.Env = append(os.Environ(), "ZTMAIL_TEST_SIGINT_INPUT=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "reading message\n" {
		t.Fatalf("input not reached: %q, %v", ready, err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatal("SIGINT did not terminate while stdin remained open")
	}
	if err == nil || !strings.Contains(stderr.String(), "read message: context canceled") {
		t.Fatalf("incorrect interrupt result: %v, stderr=%s", err, &stderr)
	}
}

func TestSIGINTMessageHelper(t *testing.T) {
	if os.Getenv("ZTMAIL_TEST_SIGINT_INPUT") != "1" {
		t.Skip("subprocess signal helper")
	}
	original := prepareMessage
	prepareMessage = func(in io.Reader, args []string, domain string, headers, dots bool) ([]byte, []string, error) {
		if _, err := io.WriteString(os.Stdout, "reading message\n"); err != nil {
			return nil, nil, err
		}
		return original(in, args, domain, headers, dots)
	}
	os.Args = []string{"ztmail", "--domain", "corp.example"}
	main()
}
