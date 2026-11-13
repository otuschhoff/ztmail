package mail

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckOutputSharedWriterCauseOnce(t *testing.T) {
	cause := errors.New("unique shared output failure")
	writer := TrackOutput(outputFailureWriter{cause: cause})
	report := NewTestReport(writer, true)
	report.Line("INFO", "Synthetic output", "required")
	err := CheckOutput(writer, report, false)
	if !errors.Is(err, cause) || !errors.Is(err, ErrOutputFailed) || strings.Count(err.Error(), cause.Error()) != 1 {
		t.Fatalf("shared writer cause duplicated or lost: %v", err)
	}
}

func TestJoinOutputPreservesDistinctCausesWithoutRepeating(t *testing.T) {
	for _, independentReport := range []bool{false, true} {
		for _, accepted := range []bool{false, true} {
			name := map[bool]string{false: "shared", true: "independent"}[independentReport] +
				map[bool]string{false: "/before", true: "/accepted"}[accepted]
			t.Run(name, func(t *testing.T) {
				writerCause := errors.New("unique writer cause")
				reportCause := writerCause
				writer := TrackOutput(outputFailureWriter{cause: writerCause})
				reportWriter := writer
				if independentReport {
					reportCause = errors.New("unique report cause")
					reportWriter = TrackOutput(outputFailureWriter{cause: reportCause})
					if _, err := writer.Write([]byte("required notice")); !errors.Is(err, writerCause) {
						t.Fatalf("seed writer failure: %v", err)
					}
				}
				report := NewTestReport(reportWriter, true)
				report.Line("INFO", "Synthetic output", "required")
				operation := errors.New("unique operation cause")
				cleanup := errors.New("unique cleanup cause")
				original := errors.Join(operation, cleanup, CheckOutput(writer, report, false))
				got := JoinOutput(original, writer, report, accepted)
				for _, cause := range []error{writerCause, reportCause, operation, cleanup} {
					if !errors.Is(got, cause) || strings.Count(got.Error(), cause.Error()) != 1 {
						t.Fatalf("cause duplicated or dropped: %v: %v", cause, got)
					}
				}
				if errors.Is(got, ErrAcceptedOutput) != accepted || errors.Is(got, ErrDeliveryUncertain) {
					t.Fatalf("acceptance classification changed: %v", got)
				}
				again := JoinOutput(got, writer, report, accepted)
				if again.Error() != got.Error() {
					t.Fatalf("deferred checkpoint repeated output: before=%v after=%v", got, again)
				}
			})
		}
	}
}

func TestJoinOutputAlreadyRetainedWriterCause(t *testing.T) {
	cause := errors.New("unique already retained cause")
	writer := TrackOutput(outputFailureWriter{cause: cause})
	report := NewTestReport(writer, true)
	report.Line("INFO", "Synthetic output", "required")
	got := JoinOutput(cause, writer, report, true)
	if !errors.Is(got, ErrAcceptedOutput) || !errors.Is(got, cause) || strings.Count(got.Error(), cause.Error()) != 1 {
		t.Fatalf("already retained writer cause repeated: %v", got)
	}
}

func TestJoinOutputRetainsAcceptedClassification(t *testing.T) {
	cause := errors.New("unique accepted writer cause")
	writer := TrackOutput(outputFailureWriter{cause: cause})
	if _, err := writer.Write([]byte("accepted notice")); !errors.Is(err, cause) {
		t.Fatalf("seed writer failure: %v", err)
	}
	original := CheckOutput(writer, nil, true)
	got := JoinOutput(original, writer, nil, false)
	if !errors.Is(got, ErrAcceptedOutput) || errors.Is(got, ErrOutputFailed) ||
		errors.Is(got, ErrDeliveryUncertain) || strings.Count(got.Error(), cause.Error()) != 1 {
		t.Fatalf("accepted classification changed or cause repeated: %v", got)
	}
}
