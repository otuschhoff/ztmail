package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"gopkg.in/jcmturner/gokrb5.v7/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/credentials"
	"gopkg.in/jcmturner/gokrb5.v7/crypto"
	"gopkg.in/jcmturner/gokrb5.v7/gssapi"
	"gopkg.in/jcmturner/gokrb5.v7/iana/flags"
	"gopkg.in/jcmturner/gokrb5.v7/iana/keyusage"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/messages"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
	"gopkg.in/jcmturner/gokrb5.v7/types"
)

func newSecurityContext(o options) (securityContext, error) {
	backend := o.auth
	if backend == "auto" {
		switch {
		case o.keytab != "":
			backend = "keytab"
		case o.ccache != "":
			backend = "ccache"
		case runtime.GOOS == "windows":
			backend = "sspi"
		default:
			backend = "ccache"
		}
	}
	if backend == "sspi" {
		if o.krbConfig != "" {
			return nil, errors.New("--krb5-config does not apply to SSPI; Windows manages KDC configuration")
		}
		return newSSPIContext(o.spn)
	}
	cfg, err := kerberosConfig(o)
	if err != nil {
		return nil, err
	}
	var cl *client.Client
	if backend == "keytab" {
		kt, err := keytab.Load(o.keytab)
		if err != nil {
			return nil, fmt.Errorf("load keytab: %w", err)
		}
		name, err := keytabPrincipal(kt, o.principal, o.realm)
		if err != nil {
			return nil, err
		}
		cl = client.NewClientWithKeytab(name, o.realm, kt, cfg, client.DisablePAFXFAST(true))
		if err := cl.Login(); err != nil {
			cl.Destroy()
			return nil, fmt.Errorf("keytab login: %w", err)
		}
	} else {
		path := o.ccache
		if path == "" {
			path = os.Getenv("KRB5CCNAME")
		}
		if path == "" {
			if runtime.GOOS == "windows" {
				return nil, errors.New("--auth ccache on Windows requires --ccache or KRB5CCNAME")
			}
			path = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
		}
		path, err = cachePath(path)
		if err != nil {
			return nil, err
		}
		cache, err := credentials.LoadCCache(path)
		if err != nil {
			return nil, fmt.Errorf("load credential cache %q (run kinit or specify --keytab): %w", path, err)
		}
		cl, err = client.NewClientFromCCache(cache, cfg, client.DisablePAFXFAST(true))
		if err != nil {
			if cl != nil {
				cl.Destroy()
			}
			return nil, fmt.Errorf("initialize credential cache: %w", err)
		}
	}
	return &kerberosContext{client: cl, target: o.spn}, nil
}

func cachePath(path string) (string, error) {
	if strings.HasPrefix(path, "FILE:") {
		path = strings.TrimPrefix(path, "FILE:")
	} else if i := strings.IndexByte(path, ':'); i >= 0 && !(i == 1 && len(path) > 2 && (path[2] == '\\' || path[2] == '/')) {
		return "", errors.New("only FILE credential caches are supported; use kinit with KRB5CCNAME=FILE:/path or --keytab")
	}
	if path == "" {
		return "", errors.New("empty credential cache path")
	}
	return path, nil
}

func kerberosConfig(o options) (*config.Config, error) {
	path := o.krbConfig
	explicit := path != ""
	if path == "" {
		path = os.Getenv("KRB5_CONFIG")
		explicit = path != ""
	}
	if path == "" {
		path = "/etc/krb5.conf"
	}
	cfg, err := loadKerberosConfig(path, !explicit)
	if err != nil {
		return nil, err
	}
	cfg.LibDefaults.DefaultRealm = o.realm
	cfg.LibDefaults.RDNS = false
	if cfg.DomainRealm == nil {
		cfg.DomainRealm = make(config.DomainRealm)
	}
	cfg.DomainRealm[o.domain] = o.realm
	cfg.DomainRealm["."+o.domain] = o.realm
	return cfg, nil
}

func loadKerberosConfig(path string, optional bool) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if optional && errors.Is(err, os.ErrNotExist) {
		cfg := config.NewConfig()
		cfg.LibDefaults.DNSLookupKDC = true
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Kerberos config %q: %w", path, err)
	}
	cfg, err := config.NewConfigFromString(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse Kerberos config %q: %w", path, err)
	}
	return cfg, nil
}

func keytabPrincipal(kt *keytab.Keytab, requested, realm string) (string, error) {
	if requested != "" {
		name := requested
		if i := strings.LastIndexByte(name, '@'); i >= 0 {
			if name[i+1:] != realm {
				return "", errors.New("--principal realm does not match --realm/discovered realm")
			}
			name = name[:i]
		}
		if name == "" {
			return "", errors.New("empty keytab principal name")
		}
		for _, e := range kt.Entries {
			if e.Principal.Realm == realm && strings.Join(e.Principal.Components, "/") == name {
				return name, nil
			}
		}
		return "", fmt.Errorf("principal %s@%s is not present in keytab", name, realm)
	}
	names := make(map[string]bool)
	for _, e := range kt.Entries {
		if e.Principal.Realm == realm {
			names[strings.Join(e.Principal.Components, "/")] = true
		}
	}
	if len(names) != 1 {
		return "", fmt.Errorf("keytab has %d distinct principals in %s; specify --principal and/or --realm", len(names), realm)
	}
	for name := range names {
		return name, nil
	}
	return "", errors.New("keytab contains no principal")
}

type kerberosContext struct {
	client                        *client.Client
	target                        string
	key, subkey                   types.EncryptionKey
	authTime                      time.Time
	authUsec                      int
	sendSequence, receiveSequence uint64
	established                   bool
}

func (c *kerberosContext) Start() ([]byte, error) {
	ticket, key, err := c.client.GetServiceTicket(c.target)
	if err != nil {
		return nil, fmt.Errorf("get service ticket for %s: %w", c.target, err)
	}
	c.key = key
	token, err := spnego.NewKRB5TokenAPREQ(c.client, ticket, key,
		[]int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagReplay, gssapi.ContextFlagSequence},
		[]int{flags.APOptionMutualRequired})
	if err != nil {
		return nil, err
	}
	// The library does not retain its generated authenticator; recover it to verify AP-REP.
	if err := token.APReq.DecryptAuthenticator(key); err != nil {
		return nil, err
	}
	auth := token.APReq.Authenticator
	c.authTime, c.authUsec = auth.CTime, auth.Cusec
	c.sendSequence = uint64(auth.SeqNumber)
	return token.Marshal()
}

func (c *kerberosContext) Step(input []byte) ([]byte, bool, error) {
	if c.established {
		return nil, false, errors.New("Kerberos context already established")
	}
	var token spnego.KRB5Token
	if err := token.Unmarshal(input); err != nil {
		return nil, false, err
	}
	if token.IsKRBError() {
		return nil, false, token.KRBError
	}
	if !token.IsAPRep() {
		return nil, false, errors.New("expected Kerberos AP-REP")
	}
	plain, err := crypto.DecryptEncPart(token.APRep.EncPart, c.key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, false, err
	}
	var reply messages.EncAPRepPart
	if err := reply.Unmarshal(plain); err != nil {
		return nil, false, err
	}
	if !reply.CTime.Equal(c.authTime) || reply.Cusec != c.authUsec {
		return nil, false, errors.New("AP-REP timestamp does not match the initiator authenticator")
	}
	c.subkey = reply.Subkey
	c.receiveSequence = uint64(reply.SequenceNumber)
	c.established = true
	return []byte{}, true, nil
}

func (c *kerberosContext) Unwrap(input []byte) ([]byte, error) {
	if !c.established {
		return nil, errors.New("Kerberos context not established")
	}
	normalized, err := unrotateWrap(input)
	if err != nil {
		return nil, err
	}
	var token gssapi.WrapToken
	if err := token.Unmarshal(normalized, true); err != nil {
		return nil, err
	}
	if token.Flags & ^byte(5) != 0 {
		return nil, errors.New("expected an RFC 4121 integrity-only wrap token (AES Kerberos keys required)")
	}
	key := c.key
	if token.Flags&4 != 0 {
		if len(c.subkey.KeyValue) == 0 {
			return nil, errors.New("server selected a missing acceptor subkey")
		}
		key = c.subkey
	}
	if _, err := token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, fmt.Errorf("invalid server wrap checksum: %w", err)
	}
	if token.SndSeqNum != c.receiveSequence {
		return nil, errors.New("server wrap token has an unexpected sequence number")
	}
	c.receiveSequence++
	return token.Payload, nil
}

func (c *kerberosContext) Wrap(payload []byte) ([]byte, error) {
	if !c.established {
		return nil, errors.New("Kerberos context not established")
	}
	key, flag := c.key, byte(0)
	if len(c.subkey.KeyValue) != 0 {
		key, flag = c.subkey, 4
	}
	token, err := gssapi.NewInitiatorWrapToken(payload, key)
	if err != nil {
		return nil, err
	}
	token.Flags, token.SndSeqNum, token.CheckSum = flag, c.sendSequence, nil
	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	c.sendSequence++
	return token.Marshal()
}

func unrotateWrap(input []byte) ([]byte, error) {
	if len(input) <= gssapi.HdrLen {
		return nil, errors.New("GSSAPI wrap token is too short")
	}
	out := append([]byte(nil), input...)
	body := out[gssapi.HdrLen:]
	rotation := int(binary.BigEndian.Uint16(out[6:8])) % len(body)
	if rotation != 0 {
		copy(body, append(append([]byte(nil), body[rotation:]...), body[:rotation]...))
	}
	binary.BigEndian.PutUint16(out[6:8], 0)
	return out, nil
}

func (c *kerberosContext) Close() error {
	c.client.Destroy()
	c.key, c.subkey = types.EncryptionKey{}, types.EncryptionKey{}
	return nil
}
