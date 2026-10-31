package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func computerName(format uintptr) (string, error) {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetComputerNameExW")
	// A DNS name is at most 253 characters; the larger buffer also accommodates Windows limits.
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	ok, _, err := proc.Call(format, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if ok == 0 {
		return "", fmt.Errorf("GetComputerNameExW: %w", err)
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

func platformHostname() (string, error) { return computerName(3) } // ComputerNameDnsFullyQualified
func platformDomain() (string, error)   { return computerName(2) } // ComputerNameDnsDomain
