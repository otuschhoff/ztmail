package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type callbackReportWriter struct {
	report          *TestReport
	output          bytes.Buffer
	recursive, once bool
	fail            bool
	entered, resume chan struct{}
}

func (w *callbackReportWriter) Write(p []byte) (int, error) {
	if !w.once {
		w.once = true
		if w.entered != nil {
			close(w.entered)
			<-w.resume
		}
		w.report.Value("Writer callback", "recorded")
		if w.recursive {
			w.report.Line("WARN", "Nested", "callback")
		}
	}
	if w.fail {
		return 0, &callbackReportError{w.report}
	}
	return w.output.Write(p)
}

type callbackReportError struct{ report *TestReport }

func (e *callbackReportError) Error() string {
	e.report.Value("Error callback", "recorded")
	return "callback writer/operation failed"
}

func TestReportWriterReentry(t *testing.T) {
	if mode := os.Getenv("ZTMAIL_REPORT_WRITER_CALLBACK"); mode != "" {
		writer := &callbackReportWriter{recursive: strings.Contains(mode, "recursive"),
			fail: mode == "line-error" || mode == "finish-error"}
		verbose := strings.HasPrefix(mode, "line")
		report := NewTestReport(writer, verbose)
		writer.report = report
		if mode == "slow-value" {
			writer.entered, writer.resume = make(chan struct{}), make(chan struct{})
			report.verbose = true
			done := make(chan struct{})
			go func() {
				defer close(done)
				report.Line("INFO", "Outer", "payload")
			}()
			<-writer.entered
			report.Value("Concurrent observer", "recorded before writer returned")
			close(writer.resume)
			<-done
		} else if verbose {
			report.Line("INFO", "Outer", "payload")
		}
		var err error
		if mode == "finish-operation-error" {
			err = &callbackReportError{report}
		}
		report.Finish(&err)
		if writer.fail || mode == "finish-operation-error" {
			var callbackErr *callbackReportError
			if !errors.As(err, &callbackErr) || report.values["Error callback"] != "recorded" {
				t.Fatalf("reentrant error identity/state lost: %v", err)
			}
			return
		}
		if err != nil || report.values["Writer callback"] != "recorded" {
			t.Fatalf("callback/error lost: err=%v values=%v", err, report.values)
		}
		if writer.recursive {
			found := false
			for _, row := range report.rows {
				found = found || row.step == "Nested"
			}
			if !found {
				t.Fatal("recursive Line was dropped")
			}
			if verbose {
				output := writer.output.String()
				first := strings.Index(output, "[INFO] Outer: payload\n")
				nested := strings.Index(output, "[WARN] Nested: callback\n")
				if first < 0 || nested <= first || strings.Count(output, "[WARN] Nested: callback\n") != 1 {
					t.Fatalf("output not ordered/exactly once: %q", output)
				}
			}
		}
		return
	}
	for _, mode := range []string{"line-value", "finish-value", "line-recursive", "finish-recursive", "slow-value",
		"line-error", "finish-error", "finish-operation-error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReportWriterReentry$", "-test.timeout=3s")
			command.Env = append(os.Environ(), "ZTMAIL_REPORT_WRITER_CALLBACK="+mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("writer callback failed or deadlocked: %v\n%s", err, output)
			}
		})
	}
}

type reportFailureWriter struct {
	err   error
	short bool
	calls int
}

func (w *reportFailureWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

func TestReportWriterFailureIdentity(t *testing.T) {
	writeErr := errors.New("report output unavailable")
	operationErr := errors.New("operation rejected")
	for _, tc := range []struct {
		name    string
		verbose bool
		short   bool
	}{
		{"verbose error", true, false},
		{"concise error", false, false},
		{"verbose short", true, true},
		{"concise short", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := &reportFailureWriter{err: writeErr, short: tc.short}
			report := NewTestReport(writer, tc.verbose)
			report.Line("INFO", "Message submission", "disabled")
			err := errors.Join(operationErr, report.OutputError())
			report.Finish(&err)
			want := writeErr
			if tc.short {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, operationErr) || !errors.Is(err, want) {
				t.Fatalf("lost operational/output cause: %v", err)
			}
			if strings.Count(err.Error(), want.Error()) != 1 {
				t.Fatalf("repeated retained output failure: %v", err)
			}
			if writer.calls != 1 {
				t.Fatalf("writer retried after failure: %d calls", writer.calls)
			}
		})
	}
}

type blockedReportWriter struct {
	entered, resume chan struct{}
	err             error
}

func (w blockedReportWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.resume
	return 0, w.err
}

func TestReportOutputBarrierAndObserverProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writeErr := errors.New("delayed output failure")
		writer := blockedReportWriter{make(chan struct{}), make(chan struct{}), writeErr}
		report := NewTestReport(writer, true)
		lineDone := make(chan struct{})
		go func() {
			defer close(lineDone)
			report.Line("WARN", "First", "blocked writer")
		}()
		<-writer.entered
		report.Value("Observer", "not blocked")
		report.Line("WARN", "Queued", "retained state")
		result := make(chan error, 1)
		go func() { result <- report.OutputError() }()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("output barrier returned before the writer: %v", err)
		default:
		}
		close(writer.resume)
		if err := <-result; !errors.Is(err, writeErr) {
			t.Fatalf("barrier lost writer cause: %v", err)
		}
		<-lineDone
		if report.values["Observer"] != "not blocked" || len(report.rows) != 2 {
			t.Fatal("blocked/failed writer lost observer state")
		}
		if err := report.OutputError(); !errors.Is(err, writeErr) {
			t.Fatalf("output failure not sticky: %v", err)
		}
		if _, err := report.TestMessage("sender@example.test", []string{"recipient@example.test"}); !errors.Is(err, writeErr) {
			t.Fatalf("testmail ignored preceding required output failure: %v", err)
		}
	})
}

func TestReportConcurrentOutputMatchesStateOrder(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, true)
	var workers sync.WaitGroup
	for i := range 40 {
		workers.Go(func() { report.Line("WARN", fmt.Sprintf("Event %d", i), "recorded") })
	}
	workers.Wait()
	if err := report.OutputError(); err != nil {
		t.Fatal(err)
	}
	var expected strings.Builder
	for _, row := range report.rows {
		fmt.Fprintf(&expected, "[%s] %s: %s\n", row.status, row.step, row.detail)
	}
	if len(report.rows) != 40 || output.String() != expected.String() {
		t.Fatal("output order/count differs from recorded state")
	}
	if err := (*TestReport)(nil).OutputError(); err != nil {
		t.Fatalf("nil optional report: %v", err)
	}
}
