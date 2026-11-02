//go:build linux || darwin

package main

import (
	"errors"
	"os"

	"golang.org/x/term"
)

func openPasswordTerminal() (passwordTerminal, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.Join(errors.New("/dev/tty is not a terminal"), tty.Close())
	}
	return &consoleTerminal{input: tty, output: tty}, nil
}
