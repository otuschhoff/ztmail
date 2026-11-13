package mail

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

var ErrOutputFailed = errors.New("required output failed")
var ErrAcceptedOutput = errors.New("message accepted; status output failed; do not retry")

// OutputWriter retains the first output failure, including a short write.
type OutputWriter struct {
	writer io.Writer
	mu     sync.Mutex
	err    error
}

func TrackOutput(writer io.Writer) *OutputWriter {
	if tracked, ok := writer.(*OutputWriter); ok {
		return tracked
	}
	if writer == nil {
		writer = io.Discard
	}
	return &OutputWriter{writer: writer}
}

func (w *OutputWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
	return n, err
}

func (w *OutputWriter) OutputError() error {
	w.mu.Lock()
	err := w.err
	w.mu.Unlock()
	return err
}

// CheckOutput is a stage boundary, never called from a writer callback.
func CheckOutput(writer io.Writer, report *TestReport, accepted bool) error {
	return JoinOutput(nil, writer, report, accepted)
}

// JoinOutput adds only output causes and classification missing from err.
func JoinOutput(err error, writer io.Writer, report *TestReport, accepted bool) error {
	var writerCause error
	if tracked, ok := writer.(interface{ OutputError() error }); ok {
		writerCause = tracked.OutputError()
	}
	reportCause := report.OutputError()
	if writerCause == nil && reportCause == nil {
		return err
	}
	if writerCause != nil && !errors.Is(reportCause, writerCause) && !errors.Is(err, writerCause) {
		err = errors.Join(err, writerCause)
	}
	if reportCause != nil && !errors.Is(err, reportCause) &&
		!(writerCause != nil && errors.Is(reportCause, writerCause) && errors.Is(err, writerCause)) {
		err = errors.Join(err, reportCause)
	}
	marker := ErrOutputFailed
	if accepted || errors.Is(err, ErrAcceptedOutput) {
		marker = ErrAcceptedOutput
	}
	if errors.Is(err, marker) {
		return err
	}
	return fmt.Errorf("%w: %w", marker, err)
}
