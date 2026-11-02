package mail

import (
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	for _, tc := range []struct {
		duration time.Duration
		want     string
	}{
		{0, "0.0ms"},
		{time.Nanosecond, "0.0ms"},
		{100 * time.Microsecond, "0.1ms"},
		{12345 * time.Microsecond, "12.3ms"},
		{time.Second - time.Millisecond, "999.0ms"},
		{time.Second, "1.0s"},
		{1250 * time.Millisecond, "1.2s"},
		{time.Minute + 234*time.Millisecond, "60.2s"},
		{-1500 * time.Millisecond, "-1.5s"},
	} {
		if got := formatDuration(tc.duration); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.duration, got, tc.want)
		}
	}
}
