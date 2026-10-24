package main

import "errors"

func newSSPIContext(string) (securityContext, error) {
	return nil, errors.New("SSPI is only available on Windows; use --keytab or a FILE credential cache on Linux")
}
