package main

import (
	"errors"
	"os"

	"golang.org/x/term"
)

func openPasswordTerminal() (passwordTerminal, error) {
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if !term.IsTerminal(int(input.Fd())) {
		return nil, errors.Join(errors.New("CONIN$ is not a console"), input.Close())
	}
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return nil, errors.Join(err, input.Close())
	}
	return &consoleTerminal{input: input, output: output}, nil
}
