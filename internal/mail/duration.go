package mail

import (
	"fmt"
	"time"
)

func formatDuration(duration time.Duration) string {
	if duration >= time.Second || duration <= -time.Second {
		return fmt.Sprintf("%.1fs", duration.Seconds())
	}
	return fmt.Sprintf("%.1fms", float64(duration)/float64(time.Millisecond))
}
