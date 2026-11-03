package mail

import "os"

func openClientKey(path string) (*os.File, error) {
	return os.Open(path)
}
