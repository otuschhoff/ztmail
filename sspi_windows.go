package main

import (
	"errors"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

type sspiContext struct {
	credentials *sspi.Credentials
	context     *kerberos.ClientContext
	target      string
	established bool
}

func newSSPIContext(target string) (securityContext, error) {
	credentials, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	return &sspiContext{credentials: credentials, target: target}, nil
}

func (c *sspiContext) Start() ([]byte, error) {
	var token []byte
	var err error
	c.context, c.established, token, err = kerberos.NewClientContextWithFlags(c.credentials, c.target,
		sspi.ISC_REQ_MUTUAL_AUTH|sspi.ISC_REQ_INTEGRITY|sspi.ISC_REQ_REPLAY_DETECT|sspi.ISC_REQ_SEQUENCE_DETECT)
	return token, err
}

func (c *sspiContext) Step(input []byte) ([]byte, bool, error) {
	done, token, err := c.context.Update(input)
	if err == nil && done {
		err = c.context.VerifyFlags()
		c.established = err == nil
	}
	return token, done, err
}

func (c *sspiContext) Unwrap(input []byte) ([]byte, error) {
	if !c.established {
		return nil, errors.New("SSPI context not established")
	}
	_, plain, err := c.context.DecryptMessage(input, 0)
	return plain, err
}

func (c *sspiContext) Wrap(payload []byte) ([]byte, error) {
	if !c.established {
		return nil, errors.New("SSPI context not established")
	}
	const secQOPWrapNoEncrypt = 0x80000001
	return c.context.EncryptMessage(payload, secQOPWrapNoEncrypt, 0)
}

func (c *sspiContext) Close() error {
	var err error
	if c.context != nil {
		err = c.context.Release()
	}
	return errors.Join(err, c.credentials.Release())
}
